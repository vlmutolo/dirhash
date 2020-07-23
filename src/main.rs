use crossbeam_channel::bounded;
use once_cell::sync::Lazy;
use std::{fs::File, io, iter, path::PathBuf, thread};
use structopt::StructOpt;
use walkdir::WalkDir;

static CLI: Lazy<Cli> = Lazy::new(|| Cli::from_args());

#[derive(StructOpt, Debug)]
#[structopt(name = "dirhash")]
struct Cli {
    #[structopt(short, long)]
    directory: PathBuf,
}

fn main() -> anyhow::Result<()> {
    // Force the config initialization to happen at the beginning.
    let _ = CLI;

    let (path_send, path_recv) = bounded::<(usize, PathBuf)>(1000);
    let (hash_send, hash_recv) = bounded::<(usize, [u8; 32])>(1000);

    // Spawn some threads to do the actual reading and
    // fingerprinting work.
    let num_threads = num_cpus::get() * 10;
    let mut hasher_threads = Vec::with_capacity(num_threads);
    for _ in 0..num_threads {
        let path_recv = path_recv.clone();
        let hash_send = hash_send.clone();
        let handle = thread::spawn(move || {
            for (id, path) in path_recv.into_iter() {
                let mut hasher = blake3::Hasher::new();

                let path_lossy = path.as_os_str().to_string_lossy();
                let path_bytes_lossy = path_lossy.as_bytes();
                hasher.update(path_bytes_lossy);

                if path.is_file() {
                    let mut file = File::open(path).unwrap();
                    io::copy(&mut file, &mut hasher).unwrap();
                }
                let hash_bytes = hasher.finalize().as_bytes().clone();
                hash_send.send((id, hash_bytes)).unwrap();
            }

            drop(hash_send);
        });
        hasher_threads.push(handle);
    }

    drop(hash_send);

    // Spawn a thread to recursively read directory contents.
    let dir_reader_thread = thread::spawn(move || {
        for (id, entry) in WalkDir::new(&CLI.directory)
            .sort_by(|a, b| a.file_name().cmp(b.file_name()))
            .into_iter()
            .enumerate()
        {
            let path = entry.unwrap().into_path();
            path_send.send((id, path)).unwrap();
        }
        drop(path_send);
    });

    // Combine the hashes into a single hash. We use the ids
    // we've been keeping track of to order them consistently
    // between runs.
    let mut file_hashes = Vec::<(usize, [u8; 32])>::new();
    let mut hasher = blake3::Hasher::new();
    let mut low_id = 0;
    for (id, hash) in hash_recv.iter() {
        file_hashes.push((id, hash));
        file_hashes.sort_unstable_by_key(|t| t.0);

    	// println!("{:?}", file_hashes.iter().map(|x| x.0).collect::<Vec<_>>());
     //    assert!(!file_hashes.iter().any(|x| x.0 == 10));

        let low_id_loc = match file_hashes.iter().position(|&x| x.0 == low_id) {
            None => continue,
            Some(idx) => idx,
        };

        let end_contiguous_ids = low_id_loc + file_hashes[low_id_loc..]
            .iter()
            .map(|x| x.0)
            .scan(low_id, |hi_id, x| {
                if x == *hi_id {
                    *hi_id += 1;
                    Some(*hi_id)
                } else {
                    None
                }
            })
            .count();

        for (_, hash) in file_hashes.drain(low_id_loc..end_contiguous_ids) {
            hasher.update(&hash);
            low_id += 1;
        }
    }

    if !file_hashes.is_empty() {
    	eprintln!("{:?}", file_hashes.iter().map(|x| x.0).collect::<Vec<_>>());
    	panic!("file_hashes should be empty.")
    }

    println!("Successfully found and hashed {} items.", low_id);
    println!("{:?}", hasher.finalize().to_hex());

    // Join the outstanding threads.
    for thread in hasher_threads
        .into_iter()
        .chain(iter::once(dir_reader_thread))
    {
        thread.join().unwrap();
    }

    Ok(())
}
