//! Bluetooth adapters communication
use log::{error, info};
use bluer::{Adapter, AdapterEvent, Address};
use futures::{Stream, StreamExt};
use tokio::sync::mpsc;
use crate::common::{AddressBT, DeviceProps};
use tokio_stream::wrappers::ReceiverStream;
use crate::global_config::CONFIG;


//region Device Scanning loop
async fn query_device_props(adapter: &Adapter, addr: Address) -> bluer::Result<DeviceProps> {
    let device = adapter.device(addr)?;
    Ok(DeviceProps {
        name: device.name().await?,
        rssi: device.rssi().await?,
        paired: device.is_paired().await?,
        connected: device.is_connected().await?,
    })
}

#[derive(Debug)]
pub enum ScanDeviceEvent {
    AddOrChangeDevice(AddressBT, DeviceProps),
    RemoveDevice(AddressBT),
}

/// Start bluetooth devices discovery and send changes to a pipe.
pub async fn scanning_loop() -> bluer::Result<impl Stream<Item=ScanDeviceEvent>> {
    let (tx, rx) = mpsc::channel(1);

    let session = bluer::Session::new().await?;
    let adapter = match &CONFIG.bluetooth_device {
        None => session.default_adapter().await?,
        Some(adapter_name) => session.adapter(adapter_name)?,
    };
    info!("Start discovering devices using Bluetooth adapter '{}'", adapter.name());
    adapter.set_powered(true).await?;

    let device_events = adapter.discover_devices_with_changes().await?;
    let mut device_events = Box::new(device_events);

    tokio::spawn(async move {
        loop {
            tokio::select! {
                Some(device_event) = device_events.next() => {
                    match device_event {
                        AdapterEvent::DeviceAdded(addr) => {
                            // println!("Device added: {}", addr);

                            let new_device_props_result = query_device_props(&adapter, addr).await;
                            match new_device_props_result {
                                Ok(props) => {
                                    // println!("{:?}", props);
                                    tx.send(ScanDeviceEvent::AddOrChangeDevice(AddressBT::new(addr.0), props)).await.unwrap();
                                    // event_matcher.on_device_add_or_change(AddressBT::new(addr.0), props)
                                },
                                Err(err) => {
                                    error!("BT scan Error: {}", &err);
                                },
                            }

                        }
                        AdapterEvent::DeviceRemoved(addr) => {
                            // println!("Device removed: {}", addr);
                            tx.send(ScanDeviceEvent::RemoveDevice(AddressBT::new(addr.0))).await.unwrap();
                            // event_matcher.on_device_remove(AddressBT::new(addr.0));
                        }
                        _ => (),
                    }
                },
                () = tx.closed() => break,
            }
        }
    });

    Ok(ReceiverStream::new(rx))
}
//endregion
