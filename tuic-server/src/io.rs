use std::sync::Arc;

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    time::{Duration, Instant},
};
use uuid::Uuid;

use crate::AppContext;

const BUFFER_SIZE: usize = 8 * 1024;
const TRAFFIC_REPORT_INTERVAL: Duration = Duration::from_secs(10); // 每10秒报告一次流量
const TRAFFIC_REPORT_THRESHOLD: usize = 1024 * 1024; // 1MB阈值，超过就立即报告

pub async fn exchange_tcp(
    a: &mut tuic_quinn::Connect,
    b: &mut tokio::net::TcpStream,
) -> (usize, usize, Option<eyre::Error>) {
    let mut a2b = [0u8; BUFFER_SIZE];
    let mut b2a = [0u8; BUFFER_SIZE];

    let mut a2b_num = 0;
    let mut b2a_num = 0;

    let mut last_err = None;

    loop {
        tokio::select! {
            a2b_res = a.recv.read(&mut a2b) => match a2b_res {
                Ok(Some(num)) => {
                    a2b_num += num;
                    if let Err(err) = b.write_all(&a2b[..num]).await {
                        last_err = Some(err.into());
                        break;
                    }
                },
                // EOF
                Ok(None) => {
                    break;
                },
                Err(err) => {
                    last_err = Some(err.into());
                    break;
                }
            },

            b2a_res = b.read(&mut b2a) => match b2a_res {
                Ok(num) => {
                    // EOF
                    if num == 0 {
                        break;
                    }
                    b2a_num += num;
                    if let Err(err) = a.send.write_all(&b2a[..num]).await {
                        last_err = Some(err.into());
                        break;
                    }
                },
                Err(err) => {
                    last_err = Some(err.into());
                    break;
                },
            }

        }
    }

    (a2b_num, b2a_num, last_err)
}

pub async fn exchange_tcp_with_realtime_stats(
    a: &mut tuic_quinn::Connect,
    b: &mut tokio::net::TcpStream,
    ctx: Arc<AppContext>,
    uuid: Uuid,
) -> (usize, usize, Option<eyre::Error>) {
    let mut a2b = [0u8; BUFFER_SIZE];
    let mut b2a = [0u8; BUFFER_SIZE];

    let mut a2b_num = 0;
    let mut b2a_num = 0;

    // 用于实时流量报告
    let mut a2b_unreported = 0;
    let mut b2a_unreported = 0;
    let mut last_report_time = Instant::now();

    let mut last_err = None;

    loop {
        tokio::select! {
            a2b_res = a.recv.read(&mut a2b) => match a2b_res {
                Ok(Some(num)) => {
                    a2b_num += num;
                    a2b_unreported += num;
                    if let Err(err) = b.write_all(&a2b[..num]).await {
                        last_err = Some(err.into());
                        break;
                    }

                    // 检查是否需要实时报告流量
                    let should_report = a2b_unreported >= TRAFFIC_REPORT_THRESHOLD
                        || b2a_unreported >= TRAFFIC_REPORT_THRESHOLD
                        || last_report_time.elapsed() >= TRAFFIC_REPORT_INTERVAL;

                    if should_report && (a2b_unreported > 0 || b2a_unreported > 0) {
                        if let Some(v2board) = &ctx.v2board {
                            if !v2board.log_traffic(&uuid, a2b_unreported as u64, b2a_unreported as u64) {
                                // User doesn't exist, break to close connection
                                break;
                            }
                        }
                        a2b_unreported = 0;
                        b2a_unreported = 0;
                        last_report_time = Instant::now();
                    }
                },
                // EOF
                Ok(None) => {
                    break;
                },
                Err(err) => {
                    last_err = Some(err.into());
                    break;
                }
            },

            b2a_res = b.read(&mut b2a) => match b2a_res {
                Ok(num) => {
                    // EOF
                    if num == 0 {
                        break;
                    }
                    b2a_num += num;
                    b2a_unreported += num;
                    if let Err(err) = a.send.write_all(&b2a[..num]).await {
                        last_err = Some(err.into());
                        break;
                    }

                    // 检查是否需要实时报告流量
                    let should_report = a2b_unreported >= TRAFFIC_REPORT_THRESHOLD
                        || b2a_unreported >= TRAFFIC_REPORT_THRESHOLD
                        || last_report_time.elapsed() >= TRAFFIC_REPORT_INTERVAL;

                    if should_report && (a2b_unreported > 0 || b2a_unreported > 0) {
                        if let Some(v2board) = &ctx.v2board {
                            if !v2board.log_traffic(&uuid, a2b_unreported as u64, b2a_unreported as u64) {
                                // User doesn't exist, break to close connection
                                break;
                            }
                        }
                        a2b_unreported = 0;
                        b2a_unreported = 0;
                        last_report_time = Instant::now();
                    }
                },
                Err(err) => {
                    last_err = Some(err.into());
                    break;
                },
            }
        }
    }

    // 报告剩余的未报告流量
    if a2b_unreported > 0 || b2a_unreported > 0 {
        if let Some(v2board) = &ctx.v2board {
            v2board.log_traffic(&uuid, a2b_unreported as u64, b2a_unreported as u64);
            // Note: at connection end, we don't need to check return value as
            // connection is closing anyway
        }
    }

    (a2b_num, b2a_num, last_err)
}
