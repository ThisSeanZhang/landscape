// use futures::stream::TryStreamExt;
use landscape::{get_all_devices, get_all_wifi_devices};

/// cargo run --package landscape --bin list_dev
#[tokio::main]
async fn main() {
    let result = get_all_devices().await;
    println!("{:#?}", result);
    let result = get_all_wifi_devices().await;
    println!("{:#?}", result);
    // get_wireless_physics().await;
}

// async fn get_wireless_physics() {
//     let (connection, handle, _) = wl_nl80211::new_connection().unwrap();
//     tokio::spawn(connection);

//     let mut phy_handle = handle.wireless_physic().get().execute().await;

//     let mut msgs = Vec::new();
//     while let Some(msg) = phy_handle.try_next().await.unwrap() {
//         msgs.push(msg);
//     }
//     assert!(!msgs.is_empty());
//     for msg in msgs {
//         println!("{:?}", msg);
//     }
// }
