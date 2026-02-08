use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};

use silo_core::state::Instance;
use silo_core::store::Store;

fn make_instance(name: &str, ip: [u8; 4], path: &str, repo: &str) -> Instance {
    Instance::builder()
        .name(name.to_string())
        .ip(Ipv4Addr::new(ip[0], ip[1], ip[2], ip[3]))
        .path(PathBuf::from(path))
        .repo(PathBuf::from(repo))
        .is_worktree(false)
        .build()
}

#[tokio::test]
async fn load_empty_store() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path()).await.unwrap();
    let all = store.list_all().await.unwrap();
    assert!(all.is_empty());
    assert_eq!(store.count().await.unwrap(), 0);
}

#[tokio::test]
async fn insert_and_list_roundtrip() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path()).await.unwrap();

    let inst = make_instance("api", [127, 0, 1, 1], "/work/api", "/repo");
    store.insert(&inst).await.unwrap();

    let all = store.list_all().await.unwrap();
    assert_eq!(all.len(), 1);
    assert_eq!(all[0].name, "api");
    assert_eq!(all[0].ip, Ipv4Addr::new(127, 0, 1, 1));
}

#[tokio::test]
async fn get_and_remove() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path()).await.unwrap();

    let inst = make_instance("api", [127, 0, 1, 1], "/work/api", "/repo");
    store.insert(&inst).await.unwrap();

    let found = store.get(Path::new("/repo"), "api").await.unwrap();
    assert!(found.is_some());

    let removed = store.remove(Path::new("/repo"), "api").await.unwrap();
    assert!(removed);

    let found = store.get(Path::new("/repo"), "api").await.unwrap();
    assert!(found.is_none());
}

#[tokio::test]
async fn multiple_sequential_inserts() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path()).await.unwrap();

    for i in 0..5 {
        let name = format!("inst-{}", i);
        let ip = [127, 0, 1, (i + 1) as u8];
        let path = format!("/work/{}", name);
        store
            .insert(&make_instance(&name, ip, &path, "/repo"))
            .await
            .unwrap();
    }

    assert_eq!(store.count().await.unwrap(), 5);
}

#[tokio::test]
async fn persists_across_opens() {
    let dir = tempfile::tempdir().unwrap();

    {
        let store = Store::open(dir.path()).await.unwrap();
        store
            .insert(&make_instance("api", [127, 0, 1, 1], "/work/api", "/repo"))
            .await
            .unwrap();
    }

    let store = Store::open(dir.path()).await.unwrap();
    assert_eq!(store.count().await.unwrap(), 1);
}

#[tokio::test]
async fn resolve_by_name_inside_repo() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path()).await.unwrap();

    store
        .insert(&make_instance("api", [127, 0, 1, 1], "/work/api", "/repo"))
        .await
        .unwrap();
    store
        .insert(&make_instance("web", [127, 0, 1, 2], "/work/web", "/repo"))
        .await
        .unwrap();

    let found = store
        .resolve_instance(Some("web"), Path::new("/work/api/src"))
        .await
        .unwrap();
    assert_eq!(found.name, "web");
}

#[tokio::test]
async fn resolve_not_found() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path()).await.unwrap();
    let err = store
        .resolve_instance(Some("nope"), Path::new("/work"))
        .await;
    assert!(err.is_err());
}
