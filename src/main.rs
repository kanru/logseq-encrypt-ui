#![windows_subsystem = "windows"]

mod logger;
mod worker;

use bastion::prelude::*;
use iui::controls::{Button, HorizontalBox, Label, MultilineEntry, PasswordEntry, VerticalBox};
use iui::prelude::*;
use std::{cell::RefCell, path::PathBuf, process::exit, rc::Rc};
use tracing::Level;
use worker::worker;

#[derive(Debug, Default)]
struct State {
    path: PathBuf,
    password: String,
}

fn main() {
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(Level::INFO)
        .finish();
    tracing::subscriber::set_global_default(subscriber).expect("init tracing");
    Bastion::init();
    Bastion::start();
    // Initialize the UI
    let ui = UI::init().unwrap();

    let (input_vbox, mut open_file_button, mut encrypt_file_button, mut decrypt_file_button) = {
        let mut input_vbox = VerticalBox::new(&ui);
        let label = Label::new(&ui, "Information\n\nPlease unlink your graph first\nthen open the logseq/metadata.edn file\nto start.");
        let open_file_button = Button::new(&ui, "Open metadata.edn");
        let mut encrypt_file_button = Button::new(&ui, "Encrypt Graph");
        let mut decrypt_file_button = Button::new(&ui, "Decrypt Graph");
        input_vbox.set_padded(&ui, true);
        input_vbox.append(&ui, label, LayoutStrategy::Stretchy);
        input_vbox.append(&ui, open_file_button.clone(), LayoutStrategy::Compact);
        input_vbox.append(&ui, encrypt_file_button.clone(), LayoutStrategy::Compact);
        input_vbox.append(&ui, decrypt_file_button.clone(), LayoutStrategy::Compact);
        encrypt_file_button.disable(&ui);
        decrypt_file_button.disable(&ui);

        (
            input_vbox,
            open_file_button,
            encrypt_file_button,
            decrypt_file_button,
        )
    };

    let (output_vbox, mut log_entry) = {
        let label = Label::new(&ui, "Log");
        let log_entry = MultilineEntry::new(&ui);
        let mut output_vbox = VerticalBox::new(&ui);
        output_vbox.set_padded(&ui, true);
        output_vbox.append(&ui, label, LayoutStrategy::Compact);
        output_vbox.append(&ui, log_entry.clone(), LayoutStrategy::Stretchy);
        (output_vbox, log_entry)
    };

    let mut hbox = HorizontalBox::new(&ui);
    hbox.set_padded(&ui, true);
    hbox.append(&ui, input_vbox, LayoutStrategy::Compact);
    hbox.append(&ui, output_vbox, LayoutStrategy::Stretchy);
    // Set up the application's layout
    let mut window = Window::new(
        &ui,
        "Logseq Graph Encrypt/Decypt Helper",
        800,
        480,
        WindowType::NoMenubar,
    );
    window.set_child(&ui, hbox);
    window.show(&ui);

    let logger = Bastion::spawn(logger::logger).expect("unable to create workers");
    let logger_ref = logger.clone();
    let worker = Bastion::spawn(move |ctx| worker(ctx, logger_ref.clone()))
        .expect("unable to create workers");
    let state = Rc::new(RefCell::new(State::default()));

    open_file_button.on_clicked(&ui, {
        let ui = ui.clone();
        let window = window.clone();
        let mut encrypt_file_button = encrypt_file_button.clone();
        let mut decrypt_file_button = decrypt_file_button.clone();
        let state = state.clone();
        move |_| {
            if let Some(path) = window.open_file(&ui) {
                state.replace(State {
                    path,
                    password: "".to_string(),
                });
                encrypt_file_button.enable(&ui);
                decrypt_file_button.enable(&ui);
            }
        }
    });

    encrypt_file_button.on_clicked(&ui, {
        let ui = ui.clone();
        let open_file_button = open_file_button.clone();
        let encrypt_file_button = encrypt_file_button.clone();
        let decrypt_file_button = decrypt_file_button.clone();
        let state = state.clone();
        let worker = worker.clone();
        let mut window = window.clone();

        move |_| {
            window.disable(&ui);

            let mut vbox = VerticalBox::new(&ui);
            let password_entry = PasswordEntry::new(&ui);
            let password_label = Label::new(&ui, "Password: ");
            let mut password_hbox = HorizontalBox::new(&ui);
            password_hbox.set_padded(&ui, true);
            password_hbox.append(&ui, password_label, LayoutStrategy::Compact);
            password_hbox.append(&ui, password_entry.clone(), LayoutStrategy::Stretchy);
            let confirm_entry = PasswordEntry::new(&ui);
            let confirm_label = Label::new(&ui, "Confirm:  ");
            let mut confirm_hbox = HorizontalBox::new(&ui);
            confirm_hbox.set_padded(&ui, true);
            confirm_hbox.append(&ui, confirm_label, LayoutStrategy::Compact);
            confirm_hbox.append(&ui, confirm_entry.clone(), LayoutStrategy::Stretchy);
            let mut ok_button = Button::new(&ui, "Encrypt");
            let mut hbox = HorizontalBox::new(&ui);
            let mut message_box = Label::new(&ui, "");
            hbox.set_padded(&ui, true);
            hbox.append(&ui, message_box.clone(), LayoutStrategy::Stretchy);
            hbox.append(&ui, ok_button.clone(), LayoutStrategy::Compact);
            vbox.set_padded(&ui, true);
            vbox.append(&ui, password_hbox, LayoutStrategy::Compact);
            vbox.append(&ui, confirm_hbox, LayoutStrategy::Compact);
            vbox.append(&ui, hbox, LayoutStrategy::Compact);
            let mut dialog = Window::new(&ui, "Set Password", 400, 100, WindowType::NoMenubar);
            dialog.set_child(&ui, vbox);
            dialog.show(&ui);
            dialog.on_closing(&ui, {
                let ui = ui.clone();
                let mut window = window.clone();
                move |dialog| {
                    window.enable(&ui);
                    dialog.hide(&ui);
                    unsafe { dialog.destroy() };
                }
            });
            ok_button.on_clicked(&ui, {
                let ui = ui.clone();
                let mut dialog = dialog.clone();
                let mut window = window.clone();
                let mut open_file_button = open_file_button.clone();
                let mut encrypt_file_button = encrypt_file_button.clone();
                let mut decrypt_file_button = decrypt_file_button.clone();
                let worker = worker.clone();
                let state = state.clone();
                move |_| {
                    let password = password_entry.value(&ui);
                    let confirm = confirm_entry.value(&ui);
                    if password == "" {
                        message_box.set_text(&ui, "Password should not be blank");
                        return;
                    }
                    if password != confirm {
                        message_box.set_text(&ui, "Password is different");
                        return;
                    }
                    state.replace(State {
                        path: state.take().path,
                        password,
                    });
                    open_file_button.disable(&ui);
                    encrypt_file_button.disable(&ui);
                    decrypt_file_button.disable(&ui);
                    let state = state.borrow();
                    worker.elems()[0]
                        .tell_anonymously(worker::msg::Encrypt {
                            path: state.path.clone(),
                            password: state.password.clone(),
                        })
                        .expect("unable to send message to worker");
                    window.enable(&ui);
                    dialog.hide(&ui);
                    unsafe { dialog.destroy() };
                }
            });
        }
    });

    decrypt_file_button.on_clicked(&ui, {
        let ui = ui.clone();
        let open_file_button = open_file_button.clone();
        let encrypt_file_button = encrypt_file_button.clone();
        let decrypt_file_button = decrypt_file_button.clone();
        let state = state.clone();
        let worker = worker.clone();
        let mut window = window.clone();

        move |_| {
            window.disable(&ui);

            let mut vbox = VerticalBox::new(&ui);
            let password_entry = PasswordEntry::new(&ui);
            let password_label = Label::new(&ui, "Password: ");
            let mut password_hbox = HorizontalBox::new(&ui);
            password_hbox.set_padded(&ui, true);
            password_hbox.append(&ui, password_label, LayoutStrategy::Compact);
            password_hbox.append(&ui, password_entry.clone(), LayoutStrategy::Stretchy);
            let mut ok_button = Button::new(&ui, "Decrypt");
            let mut hbox = HorizontalBox::new(&ui);
            let mut message_box = Label::new(&ui, "");
            hbox.set_padded(&ui, true);
            hbox.append(&ui, message_box.clone(), LayoutStrategy::Stretchy);
            hbox.append(&ui, ok_button.clone(), LayoutStrategy::Compact);
            vbox.set_padded(&ui, true);
            vbox.append(&ui, password_hbox, LayoutStrategy::Compact);
            vbox.append(&ui, hbox, LayoutStrategy::Compact);
            let mut dialog = Window::new(&ui, "Enter Password", 400, 100, WindowType::NoMenubar);
            dialog.set_child(&ui, vbox);
            dialog.show(&ui);
            dialog.on_closing(&ui, {
                let ui = ui.clone();
                let mut window = window.clone();
                move |dialog| {
                    window.enable(&ui);
                    dialog.hide(&ui);
                    unsafe { dialog.destroy() };
                }
            });
            ok_button.on_clicked(&ui, {
                let ui = ui.clone();
                let mut dialog = dialog.clone();
                let mut window = window.clone();
                let mut open_file_button = open_file_button.clone();
                let mut encrypt_file_button = encrypt_file_button.clone();
                let mut decrypt_file_button = decrypt_file_button.clone();
                let worker = worker.clone();
                let state = state.clone();
                move |_| {
                    let password = password_entry.value(&ui);
                    if password == "" {
                        message_box.set_text(&ui, "Password should not be blank");
                        return;
                    }
                    state.replace(State {
                        path: state.take().path,
                        password,
                    });
                    open_file_button.disable(&ui);
                    encrypt_file_button.disable(&ui);
                    decrypt_file_button.disable(&ui);
                    let state = state.borrow();
                    worker.elems()[0]
                        .tell_anonymously(worker::msg::Decrypt {
                            path: state.path.clone(),
                            password: state.password.clone(),
                        })
                        .expect("unable to send message to worker");
                    window.enable(&ui);
                    dialog.hide(&ui);
                    unsafe { dialog.destroy() };
                }
            });
        }
    });

    window.on_closing(&ui, {
        move |_| {
            Bastion::stop();
            Bastion::block_until_stopped();
            exit(0);
        }
    });

    let mut event_loop = ui.event_loop();
    event_loop.on_tick(&ui, {
        let ui = ui.clone();
        move || {
            let answer = logger.elems()[0]
                .ask_anonymously(logger::GetLogRequest)
                .expect("unable to send message to worker");
            let answer = bastion::run!(answer).expect("failed to get log");
            msg! { answer,
                log: logger::GetLogResponse => {
                    log_entry.set_value(&ui, &log.0);
                };
                _: _ => ();
            }

            let answer = logger.elems()[0]
                .ask_anonymously(logger::GetUiStateRequest)
                .expect("unable to send message to worker");
            let answer = bastion::run!(answer).expect("failed to get ui state");
            msg! { answer,
                msg: logger::GetUiStateResponse => {
                    if msg.0 {
                        open_file_button.disable(&ui);
                        encrypt_file_button.disable(&ui);
                        decrypt_file_button.disable(&ui);
                    } else {
                        open_file_button.enable(&ui);
                    }
                };
                _: _ => ();
            }
        }
    });

    event_loop.run_delay(&ui, 100);
}
