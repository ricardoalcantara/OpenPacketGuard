use procfs::process::FDTarget;
use std::{collections::HashMap, os::unix::net::SocketAddr, rc::Rc, sync::Arc, time::Duration};
use tokio::{sync::Mutex, task::JoinHandle};

use crate::error::OPGError;

pub struct Process {
    pid: i32,
    inode: u64,
    name: String,
    stat: procfs::process::Stat,
}

#[derive(Default)]
pub struct Database {
    index: Option<Index>,
}

#[derive(Default)]
pub struct Index {
    items: Vec<Option<Process>>,
    index_inode: HashMap<u64, Vec<usize>>,
    index_pid: HashMap<i32, usize>,
    index_socket_addr: HashMap<SocketAddr, usize>,
}

impl Index {
    pub fn insert(&mut self, p: Process) {
        let len = self.items.len();
        if let Some(idx) = self.index_inode.get_mut(&p.inode) {
            idx.push(len)
        } else {
            self.index_inode.insert(p.inode, vec![len]);
        }
        self.index_pid.insert(p.pid, len);
        self.items.push(Some(p));
    }

    pub fn take_by_inode(&mut self, inode: u64) -> Vec<Process> {
        let mut result = Vec::new();

        let Some(idx) = self.index_inode.remove(&inode) else {
            return result;
        };

        for i in idx {
            let Some(p) = self.items[i].take() else {
                continue;
            };

            self.index_pid.remove(&p.pid);
            result.push(p);
        }

        return result;
    }

    pub fn take_by_pid(&mut self, pid: i32) -> Option<Process> {
        let Some(idx) = self.index_pid.remove(&pid) else {
            return None;
        };
        let Some(p) = self.items[idx].take() else {
            return None;
        };

        self.index_inode.remove(&p.inode);

        return Some(p);
    }

    pub fn print(&self) {
        for process in &self.items {
            if let Some(p) = process {
                println!("{} {} {}", p.inode, p.pid, p.name);
            } else {
                println!("None")
            }
        }
    }

    pub fn len(&self) -> usize {
        self.items.len()
    }
}

impl Database {
    pub fn new() -> Self {
        Database {
            index: Some(Index::default()),
        }
    }

    pub fn new_shared() -> Arc<Mutex<Self>> {
        Arc::new(Mutex::new(Self::new()))
    }

    pub fn insert(&mut self, p: Process) {
        todo!()
    }

    pub fn sync(&mut self, mut processes: Vec<Process>) {
        let Some(mut old_index) = self.index.take() else {
            panic!(
                "There is no index created: file {} line {}",
                file!(),
                line!()
            );
        };
        let mut new_index = Index::default();

        for mut p in processes.drain(..) {
            if let Some(item) = old_index.take_by_pid(p.pid) {
                p.stat = item.stat;
            }
            new_index.insert(p);
        }

        if old_index.len() > 0 {
            println!("Apps closed {}", old_index.len());
            // old_index.print();
            println!("--------");
        }

        self.index = Some(new_index);
    }

    pub fn print(&self) {
        self.index.as_ref().unwrap().print();
    }
}

#[derive(Default)]
pub struct Monitor {
    database: Arc<Mutex<Database>>,
    syncing: Option<JoinHandle<Result<(), OPGError>>>,
    capturing: Option<JoinHandle<Result<(), OPGError>>>,
    pid: u32,
}

impl Monitor {
    pub fn new() -> Self {
        let pid = std::process::id();
        Monitor {
            database: Database::new_shared(),
            pid,
            ..Default::default()
        }
    }

    pub fn start(&mut self) {
        let database = self.database.clone();
        let syncing: JoinHandle<Result<(), OPGError>> = tokio::spawn(async move {
            loop {
                let all_procs = procfs::process::all_processes()?;
                let mut processes = Vec::new();
                for p in all_procs {
                    let process = p?;
                    if let (Ok(stat), Ok(fds)) = (process.stat(), process.fd()) {
                        for fd in fds {
                            if let FDTarget::Socket(inode) = fd?.target {
                                let s = stat.clone();
                                processes.push(Process {
                                    inode,
                                    pid: s.pid,
                                    name: s.comm.clone(),
                                    stat: s,
                                });
                            }
                        }
                    }
                }
                {
                    let mut locked_database = database.lock().await; // Use .await here
                    locked_database.sync(processes);
                    println!();
                    // locked_database.print();
                }

                tokio::time::sleep(Duration::from_secs(2)).await;
            }
        });

        self.syncing = Some(syncing);

        let database = self.database.clone();
        let capturing: JoinHandle<Result<(), OPGError>> = tokio::spawn(async move {
            todo!();
        });

        self.capturing = Some(capturing);
    }

    pub async fn wait(self) -> Result<(), OPGError> {
        if let Some(syncing) = self.syncing {
            return syncing.await.unwrap();
        }

        Ok(())
    }

    pub fn get_stats(&self) -> Result<(u64, u64), OPGError> {
        // let me = procfs::process::Process::myself().unwrap();
        let process = procfs::process::Process::new(self.pid as i32)?;
        let stat = process.stat()?;
        // let mem = process.statm()?;

        let cpu_usage = stat.utime + stat.stime;
        let memory = stat.vsize;
        let result = (cpu_usage, memory);

        Ok(result)
    }
}
