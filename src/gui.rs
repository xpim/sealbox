//! Graphical interface (egui/eframe).

use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;
use std::sync::mpsc::{self, Receiver};

use anyhow::{Result, anyhow};
use eframe::egui::{self, Color32, RichText};
use zeroize::Zeroizing;

use crate::archive::{self, Entry, EntryKind, Progress, Summary};
use crate::crypto::SealParams;
use crate::{MIN_PASSWORD_LEN, human_size};

pub fn run(open_sealbox: Option<PathBuf>) -> Result<()> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("Sealbox")
            .with_inner_size([760.0, 540.0])
            .with_min_inner_size([480.0, 380.0])
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
    size: u64,
}

struct OpenedBox {
    path: PathBuf,
    entries: Vec<Entry>,
    password: Zeroizing<String>,
}

struct UnlockPrompt {
    path: PathBuf,
    password: Zeroizing<String>,
    error: Option<String>,
    focus: bool,
}

enum JobDone {
    Created(Result<Summary>, PathBuf),
    Opened(Result<Vec<Entry>>, PathBuf, Zeroizing<String>),
    Extracted(Result<Summary>, PathBuf),
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
    opened: Option<OpenedBox>,
    unlock: Option<UnlockPrompt>,
    job: Option<Job>,
    status: Option<Status>,
    overwrite: bool,
}

impl App {
    fn new(open_sealbox: Option<PathBuf>) -> Self {
        let mut app = Self {
            items: Vec::new(),
            password: Zeroizing::new(String::new()),
            confirm: Zeroizing::new(String::new()),
            opened: None,
            unlock: None,
            job: None,
            status: None,
            overwrite: false,
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

    fn add_paths(&mut self, paths: impl IntoIterator<Item = PathBuf>) {
        for path in paths {
            // Same rules as the sealbox itself: each item lives at the top
            // level under its own name, so names must be unique.
            let Some(name) = path.file_name().map(|n| n.to_string_lossy().into_owned()) else {
                continue;
            };
            if self.items.iter().any(|i| i.path == path) {
                continue;
            }
            if self.items.iter().any(|i| i.name == name) {
                self.status = Some(Status::Error(format!(
                    "There is already an item named \"{name}\" in the container."
                )));
                continue;
            }
            let md = std::fs::metadata(&path);
            let is_dir = md.as_ref().is_ok_and(|m| m.is_dir());
            let size = md
                .map(|m| if m.is_file() { m.len() } else { 0 })
                .unwrap_or(0);
            self.items.push(ContainerItem {
                path,
                name,
                is_dir,
                size,
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

    fn save_sealbox(&mut self, ctx: &egui::Context) {
        let Some(mut out) = rfd::FileDialog::new()
            .set_title("Save sealbox")
            .add_filter("Sealbox", &["sbx"])
            .set_file_name("my-files.sbx")
            .save_file()
        else {
            return;
        };
        if out
            .extension()
            .is_none_or(|e| !e.eq_ignore_ascii_case("sbx"))
        {
            out.as_mut_os_string().push(".sbx");
        }
        let inputs: Vec<PathBuf> = self.items.iter().map(|i| i.path.clone()).collect();
        let pw = std::mem::replace(&mut self.password, Zeroizing::new(String::new()));
        self.confirm = Zeroizing::new(String::new());
        self.start(ctx, "Sealing…", true, move |p| {
            // The save dialog already asked about replacing an existing file.
            let r = archive::seal(
                &inputs,
                &out,
                pw.as_bytes(),
                &SealParams::default(),
                archive::DEFAULT_COMPRESSION_LEVEL,
                true,
                p,
            );
            JobDone::Created(r, out)
        });
    }

    fn extract(&mut self, ctx: &egui::Context) {
        let Some(v) = &self.opened else { return };
        let mut dialog = rfd::FileDialog::new().set_title("Unseal into folder");
        if let Some(parent) = v.path.parent() {
            dialog = dialog.set_directory(parent);
        }
        let Some(dest) = dialog.pick_folder() else {
            return;
        };
        let (path, pw, overwrite) = (v.path.clone(), v.password.clone(), self.overwrite);
        self.start(ctx, "Unsealing…", true, move |p| {
            JobDone::Extracted(
                archive::unseal(
                    &path,
                    pw.as_bytes(),
                    &SealParams::default(),
                    &dest,
                    overwrite,
                    p,
                ),
                dest,
            )
        });
    }

    fn poll_job(&mut self) {
        let Some(job) = &self.job else { return };
        let Ok(done) = job.rx.try_recv() else { return };
        self.job = None;
        match done {
            JobDone::Created(Ok(s), out) => {
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
                self.status = Some(Status::Info(msg));
            }
            JobDone::Created(Err(e), _) => self.status = Some(Status::Error(format!("{e:#}"))),
            JobDone::Opened(Ok(entries), path, password) => {
                self.unlock = None;
                self.opened = Some(OpenedBox {
                    path,
                    entries,
                    password,
                });
            }
            JobDone::Opened(Err(e), path, _) => {
                self.unlock = Some(UnlockPrompt {
                    path,
                    password: Zeroizing::new(String::new()),
                    error: Some(format!("{e:#}")),
                    focus: true,
                });
            }
            JobDone::Extracted(Ok(s), dest) => {
                self.status = Some(Status::Info(format!(
                    "Unsealed {} file(s), {} into {}",
                    s.files,
                    human_size(s.bytes),
                    dest.display()
                )));
            }
            JobDone::Extracted(Err(e), _) => self.status = Some(Status::Error(format!("{e:#}"))),
        }
    }

    fn handle_drops(&mut self, ctx: &egui::Context) {
        let dropped: Vec<PathBuf> = ctx.input(|i| {
            i.raw
                .dropped_files
                .iter()
                .filter_map(|f| f.path.clone())
                .collect()
        });
        if dropped.is_empty() || self.job.is_some() {
            return;
        }
        // Dropping a single .sbx file opens it; anything else goes into
        // the container.
        if dropped.len() == 1 && crate::is_sealbox_path(&dropped[0]) {
            self.ask_unlock(dropped[0].clone());
        } else {
            self.opened = None;
            self.add_paths(dropped);
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
                if self.opened.is_some() && ui.button("Back to container").clicked() {
                    self.opened = None; // drops and zeroizes the password
                }
            });
        });
    }

    fn container_view(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        let hovering = ctx.input(|i| !i.raw.hovered_files.is_empty());

        egui::TopBottomPanel::bottom("save_panel").show_inside(ui, |ui| {
            ui.add_space(6.0);
            let ready = !self.items.is_empty();
            let long_enough = self.password.chars().count() >= MIN_PASSWORD_LEN;
            let matches = *self.password == *self.confirm;
            egui::Grid::new("pw_grid")
                .num_columns(2)
                .spacing([8.0, 6.0])
                .show(ui, |ui| {
                    ui.label("Password:");
                    ui.add(
                        egui::TextEdit::singleline(&mut *self.password)
                            .password(true)
                            .desired_width(260.0),
                    );
                    ui.end_row();
                    ui.label("Confirm:");
                    ui.add(
                        egui::TextEdit::singleline(&mut *self.confirm)
                            .password(true)
                            .desired_width(260.0),
                    );
                    ui.end_row();
                });
            ui.horizontal(|ui| {
                let hint = if !ready {
                    "Add files first."
                } else if !long_enough {
                    "Password must be at least 8 characters. Longer is stronger."
                } else if !matches {
                    "Passwords do not match."
                } else {
                    "There is no way to recover the contents without this password."
                };
                let ok = ready && long_enough && matches;
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

        egui::CentralPanel::default().show_inside(ui, |ui| {
            ui.horizontal(|ui| {
                ui.label(RichText::new(format!("Container: {} item(s)", self.items.len())).strong());
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui.add_enabled(!self.items.is_empty(), egui::Button::new("Clear")).clicked() {
                        self.items.clear();
                    }
                    if ui.button("Add folder…").clicked()
                        && let Some(dirs) = rfd::FileDialog::new().pick_folders() {
                            self.add_paths(dirs);
                        }
                    if ui.button("Add files…").clicked()
                        && let Some(files) = rfd::FileDialog::new().pick_files() {
                            self.add_paths(files);
                        }
                });
            });
            ui.add_space(4.0);

            let accent = ui.visuals().selection.bg_fill;
            let stroke = if hovering {
                egui::Stroke::new(2.0_f32, accent)
            } else {
                ui.visuals().widgets.noninteractive.bg_stroke
            };
            egui::Frame::group(ui.style()).stroke(stroke).show(ui, |ui| {
                ui.set_min_size(ui.available_size());
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
                    egui::Grid::new("items").num_columns(3).striped(true).spacing([12.0, 6.0]).show(
                        ui,
                        |ui| {
                            for (i, item) in self.items.iter().enumerate() {
                                let icon = if item.is_dir { "📁" } else { "📄" };
                                ui.label(format!("{icon} {}", item.name))
                                    .on_hover_text(item.path.display().to_string());
                                ui.label(if item.is_dir { "folder".into() } else { human_size(item.size) });
                                if ui.small_button("✖").on_hover_text("Remove").clicked() {
                                    remove = Some(i);
                                }
                                ui.end_row();
                            }
                        },
                    );
                });
                if let Some(i) = remove {
                    self.items.remove(i);
                }
            });
        });
    }

    fn sealbox_view(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        let Some(v) = &self.opened else { return };
        let files = v
            .entries
            .iter()
            .filter(|e| e.kind == EntryKind::File)
            .count();
        let total: u64 = v.entries.iter().map(|e| e.size).sum();
        let title = v
            .path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();

        egui::TopBottomPanel::bottom("extract_panel").show_inside(ui, |ui| {
            ui.add_space(6.0);
            ui.horizontal(|ui| {
                if ui
                    .button(RichText::new("📤 Unseal all to…").strong())
                    .clicked()
                {
                    self.extract(ctx);
                }
                ui.checkbox(&mut self.overwrite, "Overwrite existing files");
            });
            ui.add_space(4.0);
        });

        egui::CentralPanel::default().show_inside(ui, |ui| {
            let Some(v) = &self.opened else { return };
            ui.label(
                RichText::new(format!(
                    "🔓 {title}: {files} file(s), {}",
                    human_size(total)
                ))
                .strong(),
            );
            ui.add_space(4.0);
            egui::Frame::group(ui.style()).show(ui, |ui| {
                ui.set_min_size(ui.available_size());
                let row_h = ui.text_style_height(&egui::TextStyle::Body) + 4.0;
                egui::ScrollArea::vertical()
                    .auto_shrink([false; 2])
                    .show_rows(ui, row_h, v.entries.len(), |ui, range| {
                        for e in &v.entries[range] {
                            ui.horizontal(|ui| {
                                let depth = e.path.matches('/').count();
                                ui.add_space(14.0 * depth as f32);
                                let name = e.path.rsplit('/').next().unwrap_or(&e.path);
                                match e.kind {
                                    EntryKind::Dir => {
                                        ui.label(format!("📁 {name}"));
                                    }
                                    EntryKind::File => {
                                        ui.label(format!("📄 {name}"));
                                        ui.label(RichText::new(human_size(e.size)).weak());
                                    }
                                }
                            });
                        }
                    });
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
                    ui.colored_label(Color32::from_rgb(220, 80, 80), err);
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
        } else if submit && !busy && !prompt.password.is_empty() {
            let path = prompt.path.clone();
            let pw = prompt.password.clone();
            prompt.error = None;
            self.start(ctx, "Unlocking…", false, move |_| {
                JobDone::Opened(
                    archive::list_contents(&path, pw.as_bytes(), &SealParams::default()),
                    path,
                    pw,
                )
            });
        }
    }
}

fn display_name(p: &Path) -> String {
    p.file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| p.display().to_string())
}

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.poll_job();
        self.handle_drops(ctx);
        if self.job.is_some() {
            ctx.request_repaint_after(std::time::Duration::from_millis(100));
        }

        let busy = self.job.is_some();

        egui::TopBottomPanel::top("top").show(ctx, |ui| {
            ui.add_space(4.0);
            ui.add_enabled_ui(!busy && self.unlock.is_none(), |ui| self.top_bar(ui));
            ui.add_space(2.0);
        });

        egui::TopBottomPanel::bottom("status").show(ctx, |ui| {
            ui.add_space(4.0);
            if let Some(job) = &self.job {
                if job.show_bar {
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
            } else {
                match &self.status {
                    Some(Status::Info(m)) => {
                        ui.colored_label(Color32::from_rgb(80, 170, 100), format!("✔ {m}"));
                    }
                    Some(Status::Error(m)) => {
                        ui.colored_label(Color32::from_rgb(220, 80, 80), format!("⚠ {m}"));
                    }
                    None => {
                        ui.label(
                            RichText::new("Compressed with zstd, encrypted with Argon2id + XChaCha20-Poly1305").weak(),
                        );
                    }
                }
            }
            ui.add_space(2.0);
        });

        egui::CentralPanel::default().show(ctx, |ui| {
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
