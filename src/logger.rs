use bastion::prelude::*;

#[derive(Debug)]
pub(crate) struct PutLogRequest(pub(crate) String);
#[derive(Debug)]
pub(crate) struct GetLogRequest;
#[derive(Debug)]
pub(crate) struct GetLogResponse(pub(crate) String);
#[derive(Debug)]
pub(crate) struct NotModified;
#[derive(Debug)]
pub(crate) enum UiToggle {
    Enable,
    Disable,
}
#[derive(Debug)]
pub(crate) struct GetUiStateRequest;
#[derive(Debug)]
pub(crate) struct GetUiStateResponse(pub(crate) bool);

pub(crate) async fn logger(ctx: BastionContext) -> Result<(), ()> {
    let mut buf = String::new();
    let mut new_logs = false;
    let mut main_ui_disabled = false;
    loop {
        msg! { ctx.recv().await?,
            ref put_log: PutLogRequest => {
                tracing::info!("{}", put_log.0);
                buf.push_str(&put_log.0);
                buf.push('\n');
                new_logs = true;
            };
            _msg: GetLogRequest =!> {
                tracing::debug!("Received get log request");
                if new_logs {
                    answer!(ctx, GetLogResponse(buf.clone())).expect("unable to send message");
                    new_logs = false;
                } else {
                    answer!(ctx, NotModified).expect("unable to send message");
                }
            };
            ref msg: UiToggle => {
                match msg {
                    UiToggle::Enable => main_ui_disabled = false,
                    UiToggle::Disable => main_ui_disabled = true,
                }
            };
            _msg: GetUiStateRequest =!> {
                tracing::debug!("Received get ui state request");
                answer!(ctx, GetUiStateResponse(main_ui_disabled)).expect("unable to send message");
            };
            m: _ => {
                tracing::warn!("Received other messages {:?}", m);
            };
        }
    }
}
