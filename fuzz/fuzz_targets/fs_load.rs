#![no_main]

use std::error::Error;

use fatfs::{Read, Write};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    #[cfg(feature = "tracing")]
    tracing_subscriber::FmtSubscriber::builder()
        .without_time()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();
    let _ = fuzz(data);
});

fn fuzz(data: &[u8]) -> Result<(), Box<dyn Error>> {
    let cursor = std::io::Cursor::new(data.to_vec());
    let fs = fatfs::FileSystem::new(cursor, fatfs::FsOptions::new())?;
    let _ = fs.fat_type();
    let _ = fs.volume_id();
    let _ = fs.volume_label_as_bytes();
    let _ = fs.cluster_size();
    let _ = fs.read_status_flags()?;
    let _ = fs.stats()?;
    let _ = fs.volume_label();
    let _ = fs.read_volume_label_from_root_dir()?;
    let _ = fs.read_volume_label_from_root_dir_as_bytes()?;

    let dir = fs.root_dir();
    let _ = dirwalk(dir, 64);

    let _ = fs.unmount()?;
    Ok(())
}

fn dirwalk<'a, IO: fatfs::ReadWriteSeek, TP: fatfs::TimeProvider, OCC: fatfs::OemCpConverter>(
    dir: fatfs::Dir<'a, IO, TP, OCC>,
    depth: usize,
) -> Option<()> {
    if depth == 0 {
        return Some(());
    }

    for direntry in dir.iter() {
        let direntry = direntry.ok()?;
        let _ = direntry.short_file_name_as_bytes();
        let _ = direntry.long_file_name_as_ucs2_units();
        let _ = direntry.file_name();
        let _ = direntry.attributes();
        let _ = direntry.len();
        let _ = direntry.created();
        let _ = direntry.accessed();
        let _ = direntry.modified();

        if direntry.is_file() {
            let mut file = direntry.to_file();
            let mut buf = [0; 20];
            let _ = file.read(&mut buf);
            let _ = file.write_all(&buf);
        }

        if direntry.is_dir() {
            let dir = direntry.to_dir();
            dir.create_file("x").ok()?;
            dir.rename("x", &dir, "y").ok()?;
            dir.remove("y").ok()?;

            dirwalk(direntry.to_dir(), depth - 1)?;
        }
    }

    Some(())
}
