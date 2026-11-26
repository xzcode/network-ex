#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
use serde::{Deserialize,Serialize};
use std::{io::Write,process::{Command,Stdio}};
use tauri::{Manager,menu::{Menu,MenuItem},tray::TrayIconBuilder,WindowEvent};
#[derive(Deserialize,Serialize)]
#[serde(deny_unknown_fields)]
struct Request {
 action:String,
 #[serde(skip_serializing_if="Option::is_none")] slot:Option<u8>,
 #[serde(skip_serializing_if="Option::is_none")] server:Option<String>,
 #[serde(skip_serializing_if="Option::is_none")] name:Option<String>,
 #[serde(skip_serializing_if="Option::is_none")] invite:Option<String>,
 #[serde(skip_serializing_if="Option::is_none")] ca_pem:Option<String>,
 #[serde(skip_serializing_if="Option::is_none")] confirm:Option<bool>,
}
fn agent_path()->Result<std::path::PathBuf,String>{
 #[cfg(debug_assertions)]
 if let Some(p)=std::env::var_os("NETWORK_EX_AGENT_BIN"){let p=std::path::PathBuf::from(p);if p.is_absolute(){return Ok(p)}}
 let exe=std::env::current_exe().map_err(|e|e.to_string())?;
 Ok(exe.parent().ok_or("missing executable directory")?.join(if cfg!(windows){"network-ex-agent.exe"}else{"network-ex-agent"}))
}
#[tauri::command]
async fn agent_request(request:Request)->Result<serde_json::Value,String>{
 if !matches!(request.action.as_str(),"list"|"status"|"diagnostics"|"enroll"|"connect"|"disconnect"|"forget"){return Err("invalid Agent action".into())}
 let payload=serde_json::to_vec(&request).map_err(|_|"invalid request")?;
 if payload.len()>65536{return Err("request too large".into())}
 tauri::async_runtime::spawn_blocking(move||{
  let mut cmd=Command::new(agent_path()?);
  cmd.arg("ctl").stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped());
  #[cfg(windows)]{use std::os::windows::process::CommandExt;cmd.creation_flags(0x08000000);}
  let mut child=cmd.spawn().map_err(|e|format!("Agent CLI: {e}"))?;
  if let Some(mut input)=child.stdin.take(){if input.write_all(&payload).is_err(){let _=child.kill();let _=child.wait();return Err("Agent input failed".into())}}
  let output=child.wait_with_output().map_err(|e|e.to_string())?;
  if !output.status.success(){return Err(String::from_utf8_lossy(&output.stderr).chars().take(400).collect())}
  if output.stdout.len()>262144{return Err("Agent response too large".into())}
  serde_json::from_slice(&output.stdout).map_err(|_|"invalid Agent response".into())
 }).await.map_err(|e|e.to_string())?
}
fn main(){
 tauri::Builder::default().setup(|app|{
  let show=MenuItem::with_id(app,"show","Show Network EX",true,None::<&str>)?;
  let quit=MenuItem::with_id(app,"quit","Quit Network EX",true,None::<&str>)?;
  let menu=Menu::with_items(app,&[&show,&quit])?;
  let mut tray=TrayIconBuilder::new().menu(&menu).tooltip("Network EX");
  if let Some(icon)=app.default_window_icon(){tray=tray.icon(icon.clone())}
  tray.on_menu_event(|app,event|match event.id.as_ref(){
   "show"=>{if let Some(w)=app.get_webview_window("main"){let _=w.show();let _=w.set_focus();}},
   "quit"=>app.exit(0),_=>{}
  }).build(app)?;
  Ok(())
 }).on_window_event(|window,event|{if let WindowEvent::CloseRequested{api,..}=event{api.prevent_close();let _=window.hide();}})
 .invoke_handler(tauri::generate_handler![agent_request]).run(tauri::generate_context!()).expect("Network EX desktop failed");
}
