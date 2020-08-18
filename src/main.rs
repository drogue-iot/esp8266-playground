#![no_std]
#![no_main]

use nucleo_f401re::{
    pac::{
        USART6,
    },
    hal::{
        prelude::*,
        gpio::{
            gpioc::{
                PC10,
                PC12,
            },
            Output,
            PushPull,
        },
        serial::{
            config::{Config, Parity, StopBits},
            Serial,
            Tx,
            Rx,
        },
    },
};

use rtic::app;
use rtic::cyccnt::{Instant, U32Ext};
use rtic::cyccnt::CYCCNT;
use rtt_logger::RTTLogger;
use rtt_target::rtt_init_print;
use rtt_target::rprintln;
//use panic_rtt_target as _;

use log::{
    set_logger,
    set_max_level,
    debug,
    info,
    error,
};

use heapless::{spsc::Queue, i, consts::{
    U1,
    U2,
    U1024,
}, Vec};

use esp8266;
use cortex_m::interrupt::enable;
use esp8266::ingress::Ingress;
use core::str::FromStr;

type SerialTx = Tx<USART6>;
type SerialRx = Rx<USART6>;
type EnablePin = PC10<Output<PushPull>>;
type ResetPin = PC12<Output<PushPull>>;

type ESPAdapter = esp8266::adapter::Adapter<'static, SerialTx>;

static LOGGER: RTTLogger = RTTLogger;

use core::{
    sync::atomic::{compiler_fence, Ordering::SeqCst},
    fmt::Write,
    panic::PanicInfo,
};
use esp8266::network::{Sockets, Socket};
use embedded_nal::{TcpStack, IpAddr, SocketAddr};

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

const DIGEST_DELAY: u32 = 100;

#[app(device = nucleo_f401re::pac, peripherals = true, monotonic = rtic::cyccnt::CYCCNT)]
const APP: () = {
    struct Resources {
        adapter: Option<ESPAdapter>,
        ingress: Ingress<'static, SerialRx>,
    }

    #[init(spawn = [digest])]
    fn init(ctx: init::Context) -> init::LateResources {
        //rtt_init_print!( BlockIfFull, 2048);
        rtt_init_print!();
        log::set_logger(&LOGGER).unwrap();
        log::set_max_level(log::LevelFilter::Trace);

        // Enable CYCNT
        let mut cmp = cortex_m::Peripherals::take().unwrap();
        cmp.DWT.enable_cycle_counter();

        let device: nucleo_f401re::pac::Peripherals = ctx.device;

        let rcc = device.RCC.constrain();
        let clocks = rcc.cfgr.sysclk(84.mhz()).freeze();

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
        let (tx, mut rx) = serial.split();

        static mut QUEUE: Queue<esp8266::protocol::Response, U2> = Queue(i::Queue::new());

        let (adapter, ingress) = esp8266::initialize(
            tx, rx,
            &mut en, &mut reset,
            unsafe { &mut QUEUE },
        ).unwrap();

        //let ingress = esp8266::adapter::Ingress::new();

        //let timer = Timer::tim3(device.TIM3, 1.hz(), clocks);

        //let (client, ingress) = builder.build(queues);
        //let esp = ESPAdapter::new(client);

        ctx.spawn.digest().unwrap();

        info!("initialized");

        init::LateResources {
            adapter: Some(adapter),
            ingress,
        }
    }

    #[task(schedule = [digest], priority = 2, resources = [ingress])]
    fn digest(mut ctx: digest::Context) {
        ctx.resources.ingress.lock(|ingress| ingress.digest());
        ctx.schedule.digest(ctx.scheduled + ( DIGEST_DELAY * 100_000).cycles())
            .unwrap();
    }

    #[task(binds = USART6, priority = 10, resources = [ingress])]
    fn usart(ctx: usart::Context) {
        ctx.resources.ingress.isr();
    }

    #[idle(resources = [adapter])]
    fn idle(ctx: idle::Context) -> ! {
        info!("idle");

        let mut adapter = ctx.resources.adapter.take().unwrap();

        let result = adapter.get_firmware_info();
        info!("firmware: {:?}", result);

        //let result = ctx.resources.adapter.send(esp8266::protocol::Command::JoinAp { ssid: "oddly", password: "scarletbegonias" });
        let result = adapter.join( "oddly", "scarletbegonias");
        info!("joined wifi {:?}", result);

        let result = adapter.get_ip_address();
        info!("IP {:?}", result);

        static mut SOCKETS: Sockets<U1, U1024> = Sockets {
            sockets: Vec( heapless::i::Vec::new() )
        };

        unsafe {
            SOCKETS.sockets.push( Socket::new() );
        }

        let network = adapter.into_network_stack( unsafe{ &mut SOCKETS} );
        info!( "network intialized");

        let socket = network.open(embedded_nal::Mode::Blocking).unwrap();
        info!( "socket {:?}", socket);

        let socket_addr = SocketAddr::new(
            IpAddr::from_str( "192.168.1.245").unwrap(),
            80,
        );

        let result = network.connect(socket, socket_addr).unwrap();

        info!("socket connected {:?}", result);

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

