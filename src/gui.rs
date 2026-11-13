//! Graphical interface (egui/eframe).

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver};

use anyhow::{Result, anyhow};
use eframe::egui::{self, Color32, RichText};
use zeroize::Zeroizing;

use crate::archive::{self, Contents, Entry, EntryKind, Progress, SealboxInfo, Summary};
use crate::crypto::SealParams;
use crate::{Strength, human_size, password_strength};

const RED: Color32 = Color32::from_rgb(220, 80, 80);
const ORANGE: Color32 = Color32::from_rgb(230, 150, 60);
const GREEN: Color32 = Color32::from_rgb(80, 170, 100);

pub fn run(open_sealbox: Option<PathBuf>) -> Result<()> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("Sealbox")
            .with_inner_size([780.0, 580.0])
            .with_min_inner_size([520.0, 420.0])
            .with_drag_and_drop(true),
        ..Default::default()
    };
    eframe::run_native(
        "Sealbox",
        options,
        Box::new(move |_cc| Ok(Box::new(App::new(open_sealbox)))),
    )
    .map_err(|e| anyhow!("could not start the GUI: {e}"))
}

struct ContainerItem {
    path: PathBuf,
    name: String,
    is_dir: bool,
    /// For folders this is filled in by a background thread.
    size: Arc<AtomicU64>,
    counting: Arc<AtomicBool>,
}

struct OpenedBox {
    path: PathBuf,
    info: SealboxInfo,
    entries: Vec<Entry>,
    selected: Vec<bool>,
    password: Zeroizing<String>,
}

impl OpenedBox {
    fn new(path: PathBuf, contents: Contents, password: Zeroizing<String>) -> Self {
        let Contents { info, entries } = contents;
        let selected = vec![false; entries.len()];
        Self {
            path,
            info,
            entries,
            selected,
            password,
        }
    }

    fn name(&self) -> String {
        display_name(&self.path)
    }

    /// Tick or untick an entry; for a folder, everything inside follows.
    fn set_selected(&mut self, i: usize, value: bool) {
        self.selected[i] = value;
        if self.entries[i].kind == EntryKind::Dir {
            let prefix = format!("{}/", self.entries[i].path);
            for (e, s) in self.entries.iter().zip(self.selected.iter_mut()) {
                if e.path.starts_with(&prefix) {
                    *s = value;
                }
            }
        }
    }

    /// Paths to pass to `unseal`: the selected entries whose parent folder is
    /// not itself selected. Empty when everything (or nothing) is selected.
    fn selection(&self) -> Vec<String> {
        if self.selected.iter().all(|s| *s) {
            return Vec::new();
        }
        let chosen: HashSet<&str> = self
            .entries
            .iter()
            .zip(&self.selected)
            .filter(|(_, s)| **s)
            .map(|(e, _)| e.path.as_str())
            .collect();
        chosen
            .iter()
            .filter(|p| !p.match_indices('/').any(|(i, _)| chosen.contains(&p[..i])))
            .map(|p| p.to_string())
            .collect()
    }

    fn selected_count(&self) -> usize {
        self.entries
            .iter()
            .zip(&self.selected)
            .filter(|(e, s)| **s && e.kind == EntryKind::File)
            .count()
    }
}

struct UnlockPrompt {
    path: PathBuf,
    password: Zeroizing<String>,
    error: Option<String>,
    focus: bool,
}

enum JobDone {
    Sealed(Result<Summary>, PathBuf),
    Opened(Result<Contents>, PathBuf, Zeroizing<String>),
    Unsealed(Result<Summary>, PathBuf),
    Verified(Result<Summary>),
    Added(Result<(Summary, Contents)>),
}

struct Job {
    label: String,
    progress: Progress,
    show_bar: bool,
    rx: Receiver<JobDone>,
}

enum Status {
    Info(String),
    Error(String),
}

struct App {
    items: Vec<ContainerItem>,
    password: Zeroizing<String>,
    confirm: Zeroizing<String>,
    /// zxcvbn result for the current password, recomputed only on change.
    strength: Option<(Zeroizing<String>, Strength)>,
    opened: Option<OpenedBox>,
    unlock: Option<UnlockPrompt>,
    job: Option<Job>,
    status: Option<Status>,
    overwrite: bool,
    /// Files dropped while a job was running, handled once it finishes.
    pending_drops: Vec<PathBuf>,
    /// The user asked to close the window during a job: cancel, then close.
    closing: bool,
}

impl App {
    fn new(open_sealbox: Option<PathBuf>) -> Self {
        let mut app = Self {
            items: Vec::new(),
            password: Zeroizing::new(String::new()),
            confirm: Zeroizing::new(String::new()),
            strength: None,
            opened: None,
            unlock: None,
            job: None,
            status: None,
            overwrite: false,
            pending_drops: Vec::new(),
            closing: false,
        };
        if let Some(p) = open_sealbox {
            app.ask_unlock(p);
        }
        app
    }

    fn ask_unlock(&mut self, path: PathBuf) {
        self.unlock = Some(UnlockPrompt {
            path,
            password: Zeroizing::new(String::new()),
            error: None,
            focus: true,
        });
    }

    fn add_paths(&mut self, ctx: &egui::Context, paths: impl IntoIterator<Item = PathBuf>) {
        for path in paths {
            // Same rules as the sealbox itself: each item lives at the top
            // level under its own name, so names must be unique.
            let Some(name) = path.file_name().map(|n| n.to_string_lossy().into_owned()) else {
                continue;
            };
            if self.items.iter().any(|i| i.path == path) {
                continue;
            }
            if self
                .items
                .iter()
                .any(|i| i.name.to_lowercase() == name.to_lowercase())
            {
                self.status = Some(Status::Error(format!(
                    "There is already an item named \"{name}\" in the container."
                )));
                continue;
            }
            let md = std::fs::metadata(&path);
            let is_dir = md.as_ref().is_ok_and(|m| m.is_dir());
            let size = Arc::new(AtomicU64::new(
                md.as_ref()
                    .map(|m| if m.is_file() { m.len() } else { 0 })
                    .unwrap_or(0),
            ));
            let counting = Arc::new(AtomicBool::new(is_dir));
            if is_dir {
                let (size, counting, ctx, path) =
                    (size.clone(), counting.clone(), ctx.clone(), path.clone());
                std::thread::spawn(move || {
                    for e in walkdir::WalkDir::new(&path).into_iter().flatten() {
                        if e.file_type().is_file() {
                            let len = e.metadata().map(|m| m.len()).unwrap_or(0);
                            size.fetch_add(len, Ordering::Relaxed);
                        }
                    }
                    counting.store(false, Ordering::Relaxed);
                    ctx.request_repaint();
                });
            }
            self.items.push(ContainerItem {
                path,
                name,
                is_dir,
                size,
                counting,
            });
        }
    }

    fn start<F>(&mut self, ctx: &egui::Context, label: &str, show_bar: bool, f: F)
    where
        F: FnOnce(&Progress) -> JobDone + Send + 'static,
    {
        let (tx, rx) = mpsc::channel();
        let progress = Progress::default();
        let p = progress.clone();
        let ctx = ctx.clone();
        std::thread::spawn(move || {
            let _ = tx.send(f(&p));
            ctx.request_repaint();
        });
        self.status = None;
        self.job = Some(Job {
            label: label.to_owned(),
            progress,
            show_bar,
            rx,
        });
    }

    fn strength(&mut self) -> &Strength {
        let stale = self
            .strength
            .as_ref()
            .is_none_or(|(pw, _)| **pw != *self.password);
        if stale {
            let s = password_strength(&self.password);
            self.strength = Some((self.password.clone(), s));
        }
        &self.strength.as_ref().unwrap().1
    }

    fn save_sealbox(&mut self, ctx: &egui::Context) {
        let Some(mut out) = rfd::FileDialog::new()
            .set_title("Save sealbox")
            .add_filter("Sealbox", &["sbx"])
            .set_file_name("my-files.sbx")
            .save_file()
        else {
            return;
        };
        // The dialog itself asked about replacing the file the user picked.
        // If we change the name by adding ".sbx", we must ask again.
        let mut overwrite = true;
        if out
            .extension()
            .is_none_or(|e| !e.eq_ignore_ascii_case("sbx"))
        {
            out.as_mut_os_string().push(".sbx");
            overwrite = false;
            if out.exists() {
                if !confirm_replace(&out) {
                    return;
                }
                overwrite = true;
            }
        }
        let inputs: Vec<PathBuf> = self.items.iter().map(|i| i.path.clone()).collect();
        // Keep the typed password until sealing succeeds, so a failed or
        // cancelled attempt does not make the user type it twice again.
        let pw = self.password.clone();
        self.start(ctx, "Sealing…", true, move |p| {
            let r = archive::seal(
                &inputs,
                &out,
                pw.as_bytes(),
                &SealParams::default(),
                archive::DEFAULT_COMPRESSION_LEVEL,
                overwrite,
                p,
            );
            JobDone::Sealed(r, out)
        });
    }

    fn unseal(&mut self, ctx: &egui::Context) {
        let Some(v) = &self.opened else { return };
        let mut dialog = rfd::FileDialog::new().set_title("Unseal into folder");
        if let Some(parent) = v.path.parent() {
            dialog = dialog.set_directory(parent);
        }
        let Some(dest) = dialog.pick_folder() else {
            return;
        };
        let only = v.selection();
        let (path, pw, overwrite) = (v.path.clone(), v.password.clone(), self.overwrite);
        self.start(ctx, "Unsealing…", true, move |p| {
            let r = archive::unseal(
                &path,
                pw.as_bytes(),
                &SealParams::default(),
                &dest,
                overwrite,
                &only,
                p,
            );
            JobDone::Unsealed(r, dest)
        });
    }

    fn verify(&mut self, ctx: &egui::Context) {
        let Some(v) = &self.opened else { return };
        let (path, pw) = (v.path.clone(), v.password.clone());
        self.start(ctx, "Verifying…", true, move |p| {
            JobDone::Verified(archive::verify(
                &path,
                pw.as_bytes(),
                &SealParams::default(),
                p,
            ))
        });
    }

    fn add_to_sealbox(&mut self, ctx: &egui::Context, inputs: Vec<PathBuf>) {
        let Some(v) = &self.opened else { return };
        if inputs.is_empty() {
            return;
        }
        let (path, pw) = (v.path.clone(), v.password.clone());
        self.start(ctx, "Adding…", true, move |p| {
            let params = SealParams::default();
            let r = archive::add(
                &path,
                &inputs,
                pw.as_bytes(),
                &params,
                archive::DEFAULT_COMPRESSION_LEVEL,
                p,
            )
            .and_then(|s| Ok((s, archive::list_contents(&path, pw.as_bytes(), &params)?)));
            JobDone::Added(r)
        });
    }

    fn poll_job(&mut self, ctx: &egui::Context) {
        let Some(job) = &self.job else { return };
        let Ok(done) = job.rx.try_recv() else { return };
        self.job = None;
        if self.closing {
            ctx.send_viewport_cmd(egui::ViewportCommand::Close);
            return;
        }
        match done {
            JobDone::Sealed(Ok(s), out) => {
                let mut msg = format!(
                    "Sealed {} file(s), {} into {} ({}{})",
                    s.files,
                    human_size(s.bytes),
                    out.display(),
                    human_size(s.sealbox_size),
                    crate::cli::ratio(s.bytes, s.sealbox_size)
                );
                if !s.warnings.is_empty() {
                    msg += &format!(
                        " ({} item(s) skipped: symlinks/special files)",
                        s.warnings.len()
                    );
                }
                self.items.clear();
                self.password = Zeroizing::new(String::new());
                self.confirm = Zeroizing::new(String::new());
                self.status = Some(Status::Info(msg));
            }
            JobDone::Opened(Ok(contents), path, password) => {
                self.unlock = None;
                self.opened = Some(OpenedBox::new(path, contents, password));
            }
            JobDone::Opened(Err(e), path, _) => {
                self.unlock = Some(UnlockPrompt {
                    path,
                    password: Zeroizing::new(String::new()),
                    error: Some(format!("{e:#}")),
                    focus: true,
                });
            }
            JobDone::Unsealed(Ok(s), dest) => {
                self.status = Some(Status::Info(format!(
                    "Unsealed {} file(s), {} into {}",
                    s.files,
                    human_size(s.bytes),
                    dest.display()
                )));
            }
            JobDone::Verified(Ok(s)) => {
                self.status = Some(Status::Info(format!(
                    "Sealbox is intact: all {} file(s), {} verified",
                    s.files,
                    human_size(s.bytes)
                )));
            }
            JobDone::Added(Ok((s, contents))) => {
                if let Some(v) = &mut self.opened {
                    v.selected = vec![false; contents.entries.len()];
                    v.entries = contents.entries;
                    // The sealbox was rewritten, so it now carries this
                    // build's version.
                    v.info = contents.info;
                }
                self.status = Some(Status::Info(format!(
                    "Added {} file(s), {}; sealbox is now {}",
                    s.files,
                    human_size(s.bytes),
                    human_size(s.sealbox_size)
                )));
            }
            JobDone::Sealed(Err(e), _)
            | JobDone::Unsealed(Err(e), _)
            | JobDone::Verified(Err(e))
            | JobDone::Added(Err(e)) => self.status = Some(Status::Error(format!("{e:#}"))),
        }
        let pending = std::mem::take(&mut self.pending_drops);
        if !pending.is_empty() {
            self.handle_dropped(ctx, pending);
        }
    }

    fn handle_drops(&mut self, ctx: &egui::Context) {
        let dropped: Vec<PathBuf> = ctx.input(|i| {
            i.raw
                .dropped_files
                .iter()
                .map(|f| f.path().to_path_buf())
                .filter(|p| !p.as_os_str().is_empty())
                .collect()
        });
        if dropped.is_empty() {
            return;
        }
        if self.job.is_some() || self.unlock.is_some() {
            // Busy: remember the drop and handle it when the job is done.
            self.pending_drops.extend(dropped);
            return;
        }
        self.handle_dropped(ctx, dropped);
    }

    fn handle_dropped(&mut self, ctx: &egui::Context, dropped: Vec<PathBuf>) {
        // A single .sbx file opens it. Other files go into the open sealbox
        // if one is shown, otherwise into the container.
        if dropped.len() == 1 && crate::is_sealbox_path(&dropped[0]) {
            self.ask_unlock(dropped[0].clone());
        } else if self.opened.is_some() {
            self.add_to_sealbox(ctx, dropped);
        } else {
            self.add_paths(ctx, dropped);
        }
    }

    fn top_bar(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.heading("🔒 Sealbox");
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui.button("Open sealbox…").clicked()
                    && let Some(p) = rfd::FileDialog::new()
                        .set_title("Open sealbox")
                        .add_filter("Sealbox", &["sbx"])
                        .pick_file()
                {
                    self.ask_unlock(p);
                }
                if self.opened.is_some() && ui.button("Close sealbox").clicked() {
                    self.opened = None; // drops and zeroizes the password
                }
            });
        });
    }

    fn drop_frame(ui: &mut egui::Ui, hovering: bool, add: impl FnOnce(&mut egui::Ui)) {
        let stroke = if hovering {
            egui::Stroke::new(2.0_f32, ui.visuals().selection.bg_fill)
        } else {
            ui.visuals().widgets.noninteractive.bg_stroke
        };
        egui::Frame::group(ui.style())
            .stroke(stroke)
            .show(ui, |ui| {
                ui.set_min_size(ui.available_size());
                add(ui);
            });
    }

    fn container_view(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        let hovering = ctx.input(|i| !i.raw.hovered_files.is_empty());

        egui::Panel::bottom("save_panel").show(ui, |ui| {
            ui.add_space(6.0);
            let ready = !self.items.is_empty();
            egui::Grid::new("pw_grid")
                .num_columns(2)
                .spacing([8.0, 6.0])
                .show(ui, |ui| {
                    ui.label("Password:");
                    ui.add(
                        egui::TextEdit::singleline(&mut *self.password)
                            .password(true)
                            .desired_width(280.0),
                    );
                    ui.end_row();
                    ui.label("Confirm:");
                    ui.add(
                        egui::TextEdit::singleline(&mut *self.confirm)
                            .password(true)
                            .desired_width(280.0),
                    );
                    ui.end_row();
                });
            let matches = *self.password == *self.confirm;
            let (score, acceptable, message) = {
                let s = self.strength();
                (s.score, s.acceptable, s.message.clone())
            };
            if !self.password.is_empty() {
                let color = match score {
                    0 | 1 => RED,
                    2 => ORANGE,
                    _ => GREEN,
                };
                ui.horizontal(|ui| {
                    ui.add(
                        egui::ProgressBar::new((score as f32 + 1.0) / 5.0)
                            .desired_width(120.0)
                            .fill(color),
                    );
                    ui.colored_label(color, message);
                });
            }
            ui.horizontal(|ui| {
                let hint = if !ready {
                    "Add files first."
                } else if !acceptable {
                    "Choose a stronger password."
                } else if !matches {
                    "Passwords do not match."
                } else {
                    "There is no way to recover the contents without this password."
                };
                let ok = ready && acceptable && matches;
                if ui
                    .add_enabled(ok, egui::Button::new(RichText::new("🔒 Seal…").strong()))
                    .clicked()
                {
                    self.save_sealbox(ctx);
                }
                ui.label(RichText::new(hint).weak());
            });
            ui.add_space(4.0);
        });

        egui::CentralPanel::default().show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.label(RichText::new(format!("Container: {} item(s)", self.items.len())).strong());
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui.add_enabled(!self.items.is_empty(), egui::Button::new("Clear")).clicked() {
                        self.items.clear();
                    }
                    if ui.button("Add folder…").clicked()
                        && let Some(dirs) = rfd::FileDialog::new().pick_folders()
                    {
                        self.add_paths(ctx, dirs);
                    }
                    if ui.button("Add files…").clicked()
                        && let Some(files) = rfd::FileDialog::new().pick_files()
                    {
                        self.add_paths(ctx, files);
                    }
                });
            });
            ui.add_space(4.0);

            Self::drop_frame(ui, hovering, |ui| {
                if self.items.is_empty() {
                    ui.centered_and_justified(|ui| {
                        ui.label(
                            RichText::new(if hovering {
                                "Release to add to the container"
                            } else {
                                "Drag and drop files or folders here\n\nor drop a .sbx file to open it"
                            })
                            .size(18.0)
                            .weak(),
                        );
                    });
                    return;
                }
                let mut remove = None;
                egui::ScrollArea::vertical().auto_shrink([false; 2]).show(ui, |ui| {
                    egui::Grid::new("items").num_columns(3).striped(true).spacing([12.0, 6.0]).show(ui, |ui| {
                        for (i, item) in self.items.iter().enumerate() {
                            let icon = if item.is_dir { "📁" } else { "📄" };
                            ui.label(format!("{icon} {}", item.name))
                                .on_hover_text(item.path.display().to_string());
                            let size = human_size(item.size.load(Ordering::Relaxed));
                            if item.counting.load(Ordering::Relaxed) {
                                ui.label(RichText::new(format!("{size}…")).weak());
                            } else {
                                ui.label(size);
                            }
                            if ui.small_button("✖").on_hover_text("Remove").clicked() {
                                remove = Some(i);
                            }
                            ui.end_row();
                        }
                    });
                });
                if let Some(i) = remove {
                    self.items.remove(i);
                }
            });
        });
    }

    fn sealbox_view(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        let hovering = ctx.input(|i| !i.raw.hovered_files.is_empty());
        let Some(v) = &self.opened else { return };
        let files = v
            .entries
            .iter()
            .filter(|e| e.kind == EntryKind::File)
            .count();
        let total: u64 = v.entries.iter().map(|e| e.size).sum();
        let chosen = v.selected_count();
        let name = v.name();

        egui::Panel::bottom("unseal_panel").show(ui, |ui| {
            ui.add_space(6.0);
            ui.horizontal(|ui| {
                let label = if chosen == 0 {
                    "📤 Unseal all to…".to_string()
                } else {
                    format!("📤 Unseal {chosen} selected to…")
                };
                if ui.button(RichText::new(label).strong()).clicked() {
                    self.unseal(ctx);
                }
                ui.checkbox(&mut self.overwrite, "Overwrite existing files");
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui
                        .button("✔ Verify")
                        .on_hover_text("Check the whole sealbox is intact")
                        .clicked()
                    {
                        self.verify(ctx);
                    }
                    if ui.button("➕ Add folder…").clicked()
                        && let Some(dirs) = rfd::FileDialog::new().pick_folders()
                    {
                        self.add_to_sealbox(ctx, dirs);
                    }
                    if ui.button("➕ Add files…").clicked()
                        && let Some(f) = rfd::FileDialog::new().pick_files()
                    {
                        self.add_to_sealbox(ctx, f);
                    }
                });
            });
            ui.add_space(4.0);
        });

        egui::CentralPanel::default().show(ui, |ui| {
            let Some(v) = &mut self.opened else { return };
            ui.horizontal(|ui| {
                ui.label(
                    RichText::new(format!(
                        "🔓 {name}: {files} file(s), {} when unsealed",
                        human_size(total)
                    ))
                    .strong(),
                );
                ui.label(
                    RichText::new(format!("· created with Sealbox {}", v.info.created_with)).weak(),
                )
                .on_hover_text(format!(
                    "Format {} (readable by Sealbox {} and newer)",
                    v.info.format, v.info.min_app
                ));
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui.small_button("Select none").clicked() {
                        v.selected.iter_mut().for_each(|s| *s = false);
                    }
                    if ui.small_button("Select all").clicked() {
                        v.selected.iter_mut().for_each(|s| *s = true);
                    }
                });
            });
            ui.add_space(4.0);
            Self::drop_frame(ui, hovering, |ui| {
                if hovering {
                    ui.centered_and_justified(|ui| {
                        ui.label(
                            RichText::new(format!("Release to add to {name}"))
                                .size(18.0)
                                .weak(),
                        );
                    });
                    return;
                }
                let row_h = ui.spacing().interact_size.y + 2.0;
                let mut toggled = None;
                egui::ScrollArea::vertical()
                    .auto_shrink([false; 2])
                    .show_rows(ui, row_h, v.entries.len(), |ui, range| {
                        for i in range {
                            let e = &v.entries[i];
                            ui.horizontal(|ui| {
                                let mut checked = v.selected[i];
                                if ui.checkbox(&mut checked, "").changed() {
                                    toggled = Some((i, checked));
                                }
                                ui.add_space(14.0 * e.path.matches('/').count() as f32);
                                let leaf = e.path.rsplit('/').next().unwrap_or(&e.path);
                                match e.kind {
                                    EntryKind::Dir => {
                                        ui.label(format!("📁 {leaf}"));
                                    }
                                    EntryKind::File => {
                                        ui.label(format!("📄 {leaf}"));
                                        ui.label(RichText::new(human_size(e.size)).weak());
                                    }
                                }
                            });
                        }
                    });
                if let Some((i, value)) = toggled {
                    v.set_selected(i, value);
                }
            });
        });
    }

    fn unlock_window(&mut self, ctx: &egui::Context) {
        let busy = self.job.is_some();
        let Some(prompt) = &mut self.unlock else {
            return;
        };
        let mut submit = false;
        let mut cancel = false;
        egui::Window::new("Unlock sealbox")
            .collapsible(false)
            .resizable(false)
            .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
            .show(ctx, |ui| {
                ui.label(display_name(&prompt.path));
                ui.add_space(4.0);
                let resp = ui.add_enabled(
                    !busy,
                    egui::TextEdit::singleline(&mut *prompt.password)
                        .password(true)
                        .hint_text("Password")
                        .desired_width(280.0),
                );
                if prompt.focus {
                    resp.request_focus();
                    prompt.focus = false;
                }
                if resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) {
                    submit = true;
                }
                if let Some(err) = &prompt.error {
                    ui.colored_label(RED, err);
                }
                ui.add_space(4.0);
                ui.horizontal(|ui| {
                    if busy {
                        ui.spinner();
                        ui.label("Deriving key…");
                    } else {
                        if ui.button("Unlock").clicked() {
                            submit = true;
                        }
                        if ui.button("Cancel").clicked() {
                            cancel = true;
                        }
                    }
                });
            });
        if cancel {
            self.unlock = None;
            let pending = std::mem::take(&mut self.pending_drops);
            if !pending.is_empty() {
                self.handle_dropped(ctx, pending);
            }
        } else if submit && !busy && !prompt.password.is_empty() {
            let path = prompt.path.clone();
            let pw = prompt.password.clone();
            prompt.error = None;
            self.start(ctx, "Unlocking…", false, move |_| {
                let r = archive::list_contents(&path, pw.as_bytes(), &SealParams::default());
                JobDone::Opened(r, path, pw)
            });
        }
    }
}

/// Ask whether to replace an existing file. Used when the app changed the
/// name the user picked (by adding ".sbx"), so the save dialog never asked.
fn confirm_replace(path: &Path) -> bool {
    rfd::MessageDialog::new()
        .set_level(rfd::MessageLevel::Warning)
        .set_title("Replace existing sealbox?")
        .set_description(format!("{} already exists. Replace it?", path.display()))
        .set_buttons(rfd::MessageButtons::YesNo)
        .show()
        == rfd::MessageDialogResult::Yes
}

fn display_name(p: &Path) -> String {
    p.file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| p.display().to_string())
}

impl eframe::App for App {
    fn ui(&mut self, root: &mut egui::Ui, _frame: &mut eframe::Frame) {
        let ctx = &root.ctx().clone();
        // Closing the window during a job would kill it mid-write. Cancel it
        // instead, and close once it has cleaned up.
        if ctx.input(|i| i.viewport().close_requested())
            && let Some(job) = &self.job
        {
            ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
            job.progress.cancel.store(true, Ordering::Relaxed);
            self.closing = true;
        }
        self.poll_job(ctx);
        self.handle_drops(ctx);
        let counting = self
            .items
            .iter()
            .any(|i| i.counting.load(Ordering::Relaxed));
        if self.job.is_some() || counting {
            ctx.request_repaint_after(std::time::Duration::from_millis(100));
        }

        let busy = self.job.is_some();

        egui::Panel::top("top").show(root, |ui| {
            ui.add_space(4.0);
            ui.add_enabled_ui(!busy && self.unlock.is_none(), |ui| self.top_bar(ui));
            ui.add_space(2.0);
        });

        egui::Panel::bottom("status").show(root, |ui| {
            ui.add_space(4.0);
            if let Some(job) = &self.job {
                if self.closing {
                    ui.horizontal(|ui| {
                        ui.spinner();
                        ui.label("Cancelling and cleaning up before closing…");
                    });
                } else if job.show_bar {
                    ui.horizontal(|ui| {
                        if ui.button("Cancel").clicked() {
                            job.progress.cancel.store(true, Ordering::Relaxed);
                        }
                        ui.add(
                            egui::ProgressBar::new(job.progress.fraction())
                                .text(&job.label)
                                .show_percentage(),
                        );
                    });
                } else {
                    ui.horizontal(|ui| {
                        ui.spinner();
                        ui.label(&job.label);
                    });
                }
                if !self.pending_drops.is_empty() && !self.closing {
                    ui.label(
                        RichText::new(format!(
                            "{} dropped item(s) will be handled when this finishes.",
                            self.pending_drops.len()
                        ))
                        .weak(),
                    );
                }
            } else {
                match &self.status {
                    Some(Status::Info(m)) => {
                        ui.colored_label(GREEN, format!("✔ {m}"));
                    }
                    Some(Status::Error(m)) => {
                        ui.colored_label(RED, format!("⚠ {m}"));
                    }
                    None => {
                        ui.label(
                            RichText::new("Compressed with zstd, encrypted with Argon2id + XChaCha20-Poly1305")
                                .weak(),
                        );
                    }
                }
            }
            ui.add_space(2.0);
        });

        egui::CentralPanel::default().show(root, |ui| {
            ui.add_enabled_ui(!busy && self.unlock.is_none(), |ui| {
                if self.opened.is_some() {
                    self.sealbox_view(ui, ctx);
                } else {
                    self.container_view(ui, ctx);
                }
            });
        });

        self.unlock_window(ctx);
    }
}
