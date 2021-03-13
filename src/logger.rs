use bastion::prelude::*;
use tracing;

#[derive(Debug)]
pub(crate) struct PutLogRequest(pub(crate) String);
#[derive(Debug)]
pub(crate) struct GetLogRequest;
#[derive(Debug)]
pub(crate) struct GetLogResponse(pub(crate) String);

pub(crate) async fn logger(ctx: BastionContext) -> Result<(), ()> {
    let mut buf = String::new();
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
            m: _ => {
                tracing::warn!("Received other messages {:?}", m);
            };
        }
    }
}
