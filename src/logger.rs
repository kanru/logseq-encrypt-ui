use bastion::prelude::*;
use tracing;

#[derive(Debug)]
pub(crate) struct PutLogRequest(pub(crate) String);
#[derive(Debug)]
pub(crate) struct GetLogRequest;
#[derive(Debug)]
pub(crate) struct GetLogResponse(pub(crate) String);
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
    let mut main_ui_disabled = false;
    loop {
        msg! { ctx.recv().await?,
            ref put_log: PutLogRequest => {
                tracing::info!("{}", put_log.0);
                buf.push_str(&put_log.0);
                buf.push('\n');
            };
            get_log: GetLogRequest =!> {
                tracing::debug!("Received get log request");
                answer!(ctx, GetLogResponse(buf.clone())).expect("unable to send message");
            };
            ref msg: UiToggle => {
                match msg {
                    UiToggle::Enable => main_ui_disabled = false,
                    UiToggle::Disable => main_ui_disabled = true,
                }
            };
            msg: GetUiStateRequest =!> {
                tracing::debug!("Received get ui state request");
                answer!(ctx, GetUiStateResponse(main_ui_disabled)).expect("unable to send message");
            };
            m: _ => {
                tracing::warn!("Received other messages {:?}", m);
            };
        }
    }
}
