use aes_gcm::aead::{Aead, KeyInit, OsRng};
use aes_gcm::{Aes256Gcm, Nonce}; // Or `Aes128Gcm`
use rand::Rng;
use rand::RngCore;
use scrypt::{scrypt, Params};
use std::env;
use std::error::Error;
use std::io::{self, BufRead, BufReader, BufWriter, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

const 帮助信息: &str = "Clip - 通用剪贴板
通过 Clip, 您可以在一个设备上复制并在另一个设备上粘贴。

用法: clip [--secure/-s] [--debug/-d] [--port/-p <端口号>] [ <address> | --help/-h ]

选项:
   --secure, -s         启用加密模式以确保数据安全
   --debug, -d          启用调试模式以显示详细日志
   --port, -p <端口号>  在指定端口号上启动一个新的剪贴板
   --help, -h           显示帮助信息

示例:
   clip                                   # 启动一个新的剪贴板
   clip --port 6666                       # 在指定端口号 6666 上启动一个新的剪贴板
   clip 192.168.86.24:53701               # 加入到 192.168.86.24:53701 的剪贴板
   clip --debug                           # 启动带有调试输出的新剪贴板
   clip --debug --secure 192.168.86.24:53701 # 加入带有调试输出并启用加密的剪贴板

默认行为:
   仅运行 `clip` 将启动一个新的剪贴板，并提供一个地址，您可以使用该地址在另一台设备上连接到相同的剪贴板。";


#[derive(Default)]
struct 配置 {
    调试模式: bool,
    加密模式: bool,
    端口: Option<u16>,
    密码: String,
    版本: String,
}

fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = env::args().collect();
    let mut 配置 = 配置 {
        版本: "dev".to_string(),
        ..Default::default()
    };

    if args.len() > 4 {
        eprintln!("参数过多");
        println!("{}", 帮助信息);
        return Ok(());
    }

    if 检查参数(&args, "--help", "-h") {
        println!("{}", 帮助信息);
        return Ok(());
    }

    if 检查参数(&args, "--debug", "-d") {
        配置.调试模式 = true;
        // 重新运行程序，去除调试参数
    }

    if 检查参数(&args, "--secure", "-s") {
        配置.加密模式 = true;
        println!("输入加密密码: ");
        io::stdin().read_line(&mut 配置.密码)?;
        配置.密码 = 配置.密码.trim().to_string();
    }

    if 检查参数(&args, "--port", "-p") {
        if let Some(端口值) = args.get(2) {
            配置.端口 = Some(端口值.parse()?);
        } else {
            eprintln!("缺少端口号");
            return Ok(());
        }
    }

    if args.len() == 2 {
        连接到服务器(&args[1], &配置)?;
    } else {
        创建服务器(&配置)?;
    }

    Ok(())
}

fn 检查参数(args: &[String], 长参数: &str, 短参数: &str) -> bool {
    args.iter().any(|arg| arg == 长参数 || arg == 短参数)
}

fn 创建服务器(配置: &配置) -> Result<(), Box<dyn Error>> {
    println!("启动一个新的剪贴板");
    let 监听地址 = if let Some(端口) = 配置.端口 {
        format!("0.0.0.0:{}", 端口)
    } else {
        "0.0.0.0:0".to_string()
    };
    let 监听器 = TcpListener::bind(&监听地址)?;
    let 本地地址 = 监听器.local_addr()?;
    println!("运行 `clip {}` 加入这个剪贴板", 本地地址);

    let 客户端列表 = Arc::new(Mutex::new(Vec::new()));

    for stream in 监听器.incoming() {
        let stream = stream?;
        let 客户端列表 = Arc::clone(&客户端列表);
        let 加密模式 = 配置.加密模式;
        let 密码 = 配置.密码.clone();
        println!("连接到设备 {}", stream.peer_addr()?);
        thread::spawn(move || 处理客户端(stream, 客户端列表, 加密模式, 密码));
    }

    Ok(())
}


fn 处理客户端(
    stream: TcpStream,
    客户端列表: Arc<Mutex<Vec<TcpStream>>>,
    加密模式: bool,
    密码: String,
) {
    {
        let mut 客户端列表 = 客户端列表.lock().unwrap();
        客户端列表.push(stream.try_clone().unwrap());
    }

    let mut 读取器 = BufReader::new(stream.try_clone().unwrap());
    let 写入器 = Arc::new(Mutex::new(BufWriter::new(stream)));

    // 启动监控线程
    let 写入器克隆 = Arc::clone(&写入器);
    let 加密模式_克隆 = 加密模式;
    let 密码_克隆 = 密码.clone();
    thread::spawn(move || 监控本地剪贴板(&写入器克隆, 加密模式_克隆, &密码_克隆));

    // 监控接收到的剪贴板
    监控接收到的剪贴板(&mut 读取器, 加密模式, &密码, 写入器);
}


fn 监控本地剪贴板(w: &Arc<Mutex<BufWriter<TcpStream>>>, 加密模式: bool, 密码: &str) {
    loop {
        let 本地剪贴板 = 获取本地剪贴板();
        // 发送剪贴板内容
        let 发送结果 = {
            let mut 写入器 = w.lock().unwrap();
            发送剪贴板(&mut *写入器, &本地剪贴板, 加密模式, 密码)
        };
        if let Err(err) = 发送结果 {
            处理错误(err);
            return;
        }
        thread::sleep(Duration::from_secs(1));
    }
}

fn 监控接收到的剪贴板(
    r: &mut BufReader<TcpStream>,
    加密模式: bool,
    密码: &str,
    _w: Arc<Mutex<BufWriter<TcpStream>>>,
) {
    loop {
        let mut 外来剪贴板字节 = vec![];
        let 读取结果 = r.read_until(b'\n', &mut 外来剪贴板字节);
        if let Err(err) = 读取结果 {
            处理错误(err);
            return;
        }

        // 解密处理
        let 外来剪贴板 = if 加密模式 {
            解密(密码.as_bytes(), &外来剪贴板字节).unwrap_or_else(|_| "".to_string())
        } else {
            String::from_utf8(外来剪贴板字节).unwrap_or_else(|_| "".to_string())
        };

        if !外来剪贴板.is_empty() {
            设置本地剪贴板(&外来剪贴板);
        }
    }
}

fn 获取本地剪贴板() -> String {
    let 输出 = if cfg!(target_os = "windows") {
        Command::new("powershell.exe")
            .arg("-command")
            .arg("Get-Clipboard")
            .output()
            .expect("获取剪贴板内容失败")
            .stdout
    } else {
        Command::new("pbpaste")
            .output()
            .expect("获取剪贴板内容失败")
            .stdout
    };

    String::from_utf8_lossy(&输出).into_owned()
}

fn 设置本地剪贴板(内容: &str) {
    let mut 命令 = if cfg!(target_os = "windows") {
        Command::new("clip")
    } else {
        Command::new("pbcopy")
    };
    let mut 子进程 = 命令.stdin(Stdio::piped()).spawn().expect("设置剪贴板内容失败");
    {
        let stdin = 子进程.stdin.as_mut().expect("获取子进程输入流失败");
        stdin.write_all(内容.as_bytes()).expect("写入剪贴板内容失败");
    }
    子进程.wait().expect("等待子进程失败");
}

fn 发送剪贴板(w: &mut BufWriter<TcpStream>, 剪贴板: &str, 加密模式: bool, 密码: &str) -> Result<(), io::Error> {
    let 剪贴板数据 = if 加密模式 {
        加密(密码.as_bytes(), 剪贴板.as_bytes()).expect("加密失败")
    } else {
        剪贴板.as_bytes().to_vec()
    };

    w.write_all(&剪贴板数据)?;
    w.write_all(b"\n")?;
    w.flush()
}


fn 加密(密码: &[u8], 数据: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    let 盐: [u8; 16] = rand::thread_rng().gen();
    let mut 密钥 = [0u8; 32];
    scrypt(密码, &盐, &Params::recommended(), &mut 密钥)?;

    let 密文 = {
        let 密码管理 = Aes256Gcm::new_from_slice(&密钥).unwrap();
        let mut 随机数 = [0u8; 12];
        OsRng.fill_bytes(&mut 随机数);
        let nonce = Nonce::from_slice(&随机数);
        密码管理
            .encrypt(nonce, 数据)
            .map_err(|_| "加密失败")?
    };

    Ok([&盐[..], &密文[..]].concat())
}

fn 解密(密码: &[u8], 数据: &[u8]) -> Result<String, Box<dyn Error>> {
    let (盐, 密文) = 数据.split_at(16);
    let mut 密钥 = [0u8; 32];
    scrypt(密码, 盐, &Params::recommended(), &mut 密钥)?;

    let 解密数据 = {
        let 密码管理 = Aes256Gcm::new_from_slice(&密钥).unwrap();
        let (随机数, 数据) = 密文.split_at(12);
        let nonce = Nonce::from_slice(随机数);
        密码管理
            .decrypt(nonce, 数据)
            .map_err(|_| "解密失败")?
    };

    Ok(String::from_utf8(解密数据)?)
}

fn 处理错误(err: io::Error) {
    eprintln!("错误: {}", err);
}

fn 连接到服务器(地址: &str, 配置: &配置) -> Result<(), Box<dyn Error>> {
    let stream = TcpStream::connect(地址)?;
    println!("已连接到剪贴板");

    let 客户端列表 = Arc::new(Mutex::new(Vec::new()));
    {
        let mut 客户端列表 = 客户端列表.lock().unwrap();
        客户端列表.push(stream.try_clone().unwrap());
    }

    let mut 读取器 = BufReader::new(stream.try_clone().unwrap());
    let 写入器 = Arc::new(Mutex::new(BufWriter::new(stream)));

    // 启动监控线程
    let 写入器克隆 = Arc::clone(&写入器);
    let 加密模式_克隆 = 配置.加密模式;
    let 密码_克隆 = 配置.密码.clone();
    thread::spawn(move || 监控本地剪贴板(&写入器克隆, 加密模式_克隆, &密码_克隆));

    // 监控接收到的剪贴板
    监控接收到的剪贴板(&mut 读取器, 配置.加密模式, &配置.密码, 写入器);

    Ok(())
}
