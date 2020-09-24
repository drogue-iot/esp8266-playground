#![no_std]
#![no_main]

use nucleo_f401re::{
    pac::{
        USART6,
    },
    hal::{
        prelude::*,
        serial::{
            config::{Config, Parity, StopBits},
            Serial,
            Tx,
            Rx,
        },
    },
};

use rtic::app;
use rtic::cyccnt::{U32Ext};
use rtt_logger::RTTLogger;
use rtt_target::rtt_init_print;
use rtt_target::rprintln;
//use panic_rtt_target as _;

use log::{info, LevelFilter};

use heapless::{
    spsc::Queue,
    i,
    consts::{
        U2,
        U16,
    },
};

use drogue_esp8266::{
    initialize,
    ingress::Ingress,
    adapter::Adapter,
    protocol::Response,
    network::Esp8266IpNetworkDriver,
};
use core::str::{FromStr};

type SerialTx = Tx<USART6>;
type SerialRx = Rx<USART6>;

type ESPAdapter = Adapter<'static, SerialTx>;

static LOGGER: RTTLogger = RTTLogger::new(LevelFilter::Debug);

use core::{
    sync::atomic::{compiler_fence, Ordering::SeqCst},
    panic::PanicInfo,
};
use drogue_network::{
    IpNetworkDriver,
    tcp::{
        Mode,
        TcpStack,
        TcpError,
    },
    addr::{
        Ipv4Addr,
        IpAddr,
    },
    dns::{
        AddrType,
    }
};
//{Mode, TcpStack, IpAddr, SocketAddr, Dns, AddrType, Ipv4Addr};

use drogue_tls::ssl::config::{Verify, Transport, Preset};
use drogue_tls::entropy::StaticEntropySource;
use drogue_tls::platform::SslPlatform;
use drogue_tls::net::tcp_stack::{SslTcpStack, TlsTcpStackError};
use drogue_network::addr::{HostSocketAddr, HostAddr};
use stm32f4xx_hal::nb::Error;

#[inline(never)]
#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    use cortex_m::interrupt;

    interrupt::disable();

    rprintln!("panic");
    rprintln!("{}", info);

    loop {
        compiler_fence(SeqCst);
    }
}

const DIGEST_DELAY: u32 = 200;

#[app(device = nucleo_f401re::pac, peripherals = true, monotonic = rtic::cyccnt::CYCCNT)]
const APP: () = {
    struct Resources {
        adapter: Option<ESPAdapter>,
        ingress: Ingress<'static, SerialRx>,
        ssl_platform: SslPlatform,
    }

    #[init(spawn = [digest])]
    fn init(ctx: init::Context) -> init::LateResources {
        // Initialize the allocator BEFORE you use it
        //let start = cortex_m_rt::heap_start() as usize;
        //let size = 1024; // in bytes
        //unsafe { ALLOCATOR.init(start, size) }

        rtt_init_print!( BlockIfFull, 2048);
        log::set_logger(&LOGGER).unwrap();
        log::set_max_level(log::LevelFilter::Info);

        let mut cmp = cortex_m::Peripherals::take().unwrap();
        cmp.DWT.enable_cycle_counter();

        let device: nucleo_f401re::pac::Peripherals = ctx.device;

        let rcc = device.RCC.constrain();
        let clocks = rcc.cfgr.sysclk(84.mhz()).freeze();

        //let mut config = SslConfig::new(Endpoint::Client, Transport::Stream, Preset::Default);
        info!("SSL init");
        let mut ssl_platform = SslPlatform::setup(
            cortex_m_rt::heap_start() as usize,
            1024 * 48).unwrap();

        info!("start entropy");
        ssl_platform.entropy_context_mut().add_source(StaticEntropySource);
        info!("finished entropy");

        info!("start rng");
        //let mut ctr_drbg = CtrDrbgContext::new();
        //ctr_drbg.seed(&mut entropy).unwrap();
        ssl_platform.seed_rng().unwrap();
        info!("finished rng");

        let gpioa = device.GPIOA.split();
        let gpioc = device.GPIOC.split();

        let pa11 = gpioa.pa11;
        let pa12 = gpioa.pa12;

// SERIAL pins for USART6
        let tx_pin = pa11.into_alternate_af8();
        let rx_pin = pa12.into_alternate_af8();

// enable pin
        let mut en = gpioc.pc10.into_push_pull_output();
// reset pin
        let mut reset = gpioc.pc12.into_push_pull_output();

        let usart6 = device.USART6;

        let mut serial = Serial::usart6(
            usart6,
            (tx_pin, rx_pin),
            Config {
                baudrate: 115_200.bps(),
                parity: Parity::ParityNone,
                stopbits: StopBits::STOP1,
                ..Default::default()
            },
            clocks,
        ).unwrap();

        serial.listen(nucleo_f401re::hal::serial::Event::Rxne);
        let (tx, rx) = serial.split();

        static mut RESPONSE_QUEUE: Queue<Response, U2> = Queue(i::Queue::new());
        static mut NOTIFICATION_QUEUE: Queue<Response, U16> = Queue(i::Queue::new());

        let (adapter, ingress) = initialize(
            tx, rx,
            &mut en, &mut reset,
            unsafe { &mut RESPONSE_QUEUE },
            unsafe { &mut NOTIFICATION_QUEUE },
        ).unwrap();

        ctx.spawn.digest().unwrap();

        info!("initialized");

        init::LateResources {
            adapter: Some(adapter),
            ingress,
            ssl_platform,
        }
    }

    #[task(schedule = [digest], priority = 2, resources = [ingress])]
    fn digest(mut ctx: digest::Context) {
        ctx.resources.ingress.lock(|ingress| ingress.digest());
        ctx.schedule.digest(ctx.scheduled + (DIGEST_DELAY * 100_000).cycles())
            .unwrap();
    }

    #[task(binds = USART6, priority = 10, resources = [ingress])]
    fn usart(ctx: usart::Context) {
        if let Err(b) = ctx.resources.ingress.isr() {
            info!("failed to ingress {}", b as char);
        }
    }

    #[idle(resources = [adapter, ssl_platform])]
    fn idle(ctx: idle::Context) -> ! {
        info!("idle");

        //let mut ssl_context = ssl_config.new_context().unwrap();
        //ssl_context.set_hostname("www.google.com");

        let mut adapter = ctx.resources.adapter.take().unwrap();

        let result = adapter.get_firmware_info();
        info!("firmware: {:?}", result);

        let result = adapter.join("oddly", "scarletbegonias");
        info!("joined wifi {:?}", result);

        let result = adapter.get_ip_address();
        info!("IP {:?}", result);

        adapter.set_dns_resolvers(
            Ipv4Addr::from_str("8.8.8.8").unwrap(),
            Some( Ipv4Addr::from_str("8.8.4.4").unwrap())
        ).unwrap();

        let resolvers = adapter.query_dns_resolvers().unwrap();
        log::info!("resolvers {:?}", resolvers);

        let network = adapter.into_network_stack();
        info!("network intialized");


        //let host = network.dns().gethostbyname("www.google.com", AddrType::IPv4).unwrap();
        let host = network.dns().gethostbyname("www.google.com", AddrType::IPv4).unwrap();
        log::info!("DNS resolve {:?}", host);

        let ssl_platform = ctx.resources.ssl_platform;
        let mut ssl_config = ssl_platform.new_client_config(Transport::Stream, Preset::Default).unwrap();
        ssl_config.authmode(Verify::None);

        // consume the config, take a non-mutable ref to the network.
        let secure_network = SslTcpStack::new(ssl_config, &network);

        let socket = secure_network.open(Mode::Blocking).unwrap();
        info!("socket {:?}", socket);

        /*
        let socket_addr = HostSocketAddr::new(
            HostAddr::from_str("192.168.1.220").unwrap(),
            8080,
        );
         */

        let socket_addr = HostSocketAddr::new(
            host,
            443,
        );

        let mut socket = secure_network.connect(socket, socket_addr).unwrap();

        secure_network.write(&mut socket, b"GET / HTTP/1.1\r\nhost:192.168.1.8\r\n\r\n").unwrap();

        loop {
            let mut buffer = [0; 128];
            let result = secure_network.read(&mut socket, &mut buffer);
            match result {
                Ok(len) => {
                    if len > 0 {
                        let s = core::str::from_utf8(&buffer[0..len]);
                        match s {
                            Ok(s) => {
                                info!("recv: {} ", s);
                            }
                            Err(_) => {
                                info!("recv: {} bytes (not utf8)", len);
                            }
                        }
                    }
                }
                Err(e) => {
                    match e {
                        Error::Other(o) => {
                            let t:TcpError = o.into();
                            info!("ERR: {:?}", t);
                        },
                        Error::WouldBlock => {},
                    }
                    break;
                }
            }
        }

        loop {
            continue;
        }
    }

    // spare interrupt used for scheduling software tasks
    extern "C" {
        fn SPI1();
        fn SPI2();
    }
};

