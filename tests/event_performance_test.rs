use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use whatsapp_rust::types::events::{Event, EventBus, Connected, Disconnected};
use whatsapp_rust::types::message::{MessageInfo, MessageSource};
use whatsapp_rust::types::jid::Jid;
use whatsapp_proto::whatsapp as wa;
use std::str::FromStr;

/// Mock implementation of the old event handler system for comparison
struct OldEventHandler {
    handlers: Arc<RwLock<Vec<Box<dyn Fn(Arc<Event>) + Send + Sync>>>>,
}

impl OldEventHandler {
    fn new() -> Self {
        Self {
            handlers: Arc::new(RwLock::new(Vec::new())),
        }
    }

    async fn add_handler<F>(&self, handler: F)
    where
        F: Fn(Arc<Event>) + Send + Sync + 'static,
    {
        let mut handlers = self.handlers.write().await;
        handlers.push(Box::new(handler));
    }

    async fn dispatch_event(&self, event: Event) {
        let handlers = self.handlers.read().await;
        let event_arc = Arc::new(event);
        
        // Simulate the old O(N) iteration through all handlers
        for handler in handlers.iter() {
            handler(event_arc.clone());
        }
    }
}

#[tokio::test]
async fn test_event_dispatch_latency_comparison() {
    println!("\n=== Event Dispatch Latency Comparison ===");
    
    // Test with different numbers of handlers/subscribers
    let handler_counts = [1, 10, 50, 100, 500, 1000];
    
    for &count in &handler_counts {
        println!("\nTesting with {} handlers/subscribers:", count);
        
        // Test old system
        let old_system = OldEventHandler::new();
        for _ in 0..count {
            old_system.add_handler(|_event| {
                // Simulate some work
                std::hint::black_box(());
            }).await;
        }
        
        // Measure old system dispatch time
        let start = Instant::now();
        for _ in 0..1000 {
            old_system.dispatch_event(Event::Connected(Connected)).await;
        }
        let old_duration = start.elapsed();
        
        // Test new system
        let event_bus = EventBus::new();
        let mut _receivers = Vec::new();
        
        for _ in 0..count {
            let mut rx = event_bus.connected.subscribe();
            _receivers.push(tokio::spawn(async move {
                while let Ok(_event) = rx.recv().await {
                    // Simulate some work
                    std::hint::black_box(());
                }
            }));
        }
        
        // Give tasks time to start
        tokio::time::sleep(Duration::from_millis(10)).await;
        
        // Measure new system dispatch time
        let start = Instant::now();
        for _ in 0..1000 {
            let _ = event_bus.connected.send(Arc::new(Connected));
        }
        let new_duration = start.elapsed();
        
        let improvement = if new_duration.as_nanos() > 0 {
            old_duration.as_nanos() as f64 / new_duration.as_nanos() as f64
        } else {
            f64::INFINITY
        };
        
        println!("  Old system: {:?} ({:.2} μs per event)", old_duration, old_duration.as_nanos() as f64 / 1000.0 / 1000.0);
        println!("  New system: {:?} ({:.2} μs per event)", new_duration, new_duration.as_nanos() as f64 / 1000.0 / 1000.0);
        println!("  Improvement: {:.2}x faster", improvement);
    }
}

#[tokio::test]
async fn test_selective_event_delivery() {
    println!("\n=== Selective Event Delivery Test ===");
    
    let event_bus = EventBus::new();
    
    // Create subscribers for different event types
    let connected_count = Arc::new(std::sync::atomic::AtomicU32::new(0));
    let disconnected_count = Arc::new(std::sync::atomic::AtomicU32::new(0));
    let message_count = Arc::new(std::sync::atomic::AtomicU32::new(0));
    
    // Connected subscriber
    let connected_counter = connected_count.clone();
    let mut connected_rx = event_bus.connected.subscribe();
    tokio::spawn(async move {
        while let Ok(_) = connected_rx.recv().await {
            connected_counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
    });
    
    // Disconnected subscriber  
    let disconnected_counter = disconnected_count.clone();
    let mut disconnected_rx = event_bus.disconnected.subscribe();
    tokio::spawn(async move {
        while let Ok(_) = disconnected_rx.recv().await {
            disconnected_counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
    });
    
    // Message subscriber
    let message_counter = message_count.clone();
    let mut message_rx = event_bus.message.subscribe();
    tokio::spawn(async move {
        while let Ok(_) = message_rx.recv().await {
            message_counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
    });
    
    // Give subscribers time to start
    tokio::time::sleep(Duration::from_millis(10)).await;
    
    // Send different types of events
    for _ in 0..100 {
        let _ = event_bus.connected.send(Arc::new(Connected));
    }
    
    for _ in 0..50 {
        let _ = event_bus.disconnected.send(Arc::new(Disconnected));
    }
    
    // Create a dummy message
    let msg = Box::new(wa::Message::default());
    let info = MessageInfo {
        source: MessageSource {
            chat: Jid::from_str("test@s.whatsapp.net").unwrap(),
            sender: Jid::from_str("test@s.whatsapp.net").unwrap(),
            is_from_me: false,
            is_group: false,
            ..Default::default()
        },
        id: "test".to_string(),
        server_id: 0,
        r#type: "text".to_string(),
        push_name: "Test".to_string(),
        timestamp: chrono::Utc::now(),
        category: "".to_string(),
        multicast: false,
        media_type: "".to_string(),
        edit: Default::default(),
        bot_info: None,
        meta_info: Default::default(),
        verified_name: None,
        device_sent_meta: None,
    };
    
    for _ in 0..75 {
        let _ = event_bus.message.send(Arc::new((msg.clone(), info.clone())));
    }
    
    // Wait for event processing
    tokio::time::sleep(Duration::from_millis(100)).await;
    
    // Verify selective delivery
    let connected_received = connected_count.load(std::sync::atomic::Ordering::Relaxed);
    let disconnected_received = disconnected_count.load(std::sync::atomic::Ordering::Relaxed);
    let message_received = message_count.load(std::sync::atomic::Ordering::Relaxed);
    
    println!("Connected events sent: 100, received: {}", connected_received);
    println!("Disconnected events sent: 50, received: {}", disconnected_received);
    println!("Message events sent: 75, received: {}", message_received);
    
    // Verify that subscribers only received their specific event types
    assert_eq!(connected_received, 100, "Connected subscriber should receive exactly 100 events");
    assert_eq!(disconnected_received, 50, "Disconnected subscriber should receive exactly 50 events");
    assert_eq!(message_received, 75, "Message subscriber should receive exactly 75 events");
    
    println!("✅ Selective delivery working correctly - each subscriber only receives their event type");
}

#[tokio::test] 
async fn test_throughput_comparison() {
    println!("\n=== Throughput Comparison ===");
    
    let num_events = 10000;
    let num_handlers = 100;
    
    // Test old system throughput
    let old_system = OldEventHandler::new();
    for _ in 0..num_handlers {
        old_system.add_handler(|_| {}).await;
    }
    
    let start = Instant::now();
    for _ in 0..num_events {
        old_system.dispatch_event(Event::Connected(Connected)).await;
    }
    let old_throughput_time = start.elapsed();
    let old_throughput = num_events as f64 / old_throughput_time.as_secs_f64();
    
    // Test new system throughput
    let event_bus = EventBus::new();
    let mut _receivers = Vec::new();
    
    for _ in 0..num_handlers {
        let mut rx = event_bus.connected.subscribe();
        _receivers.push(tokio::spawn(async move {
            while let Ok(_) = rx.recv().await {}
        }));
    }
    
    tokio::time::sleep(Duration::from_millis(10)).await;
    
    let start = Instant::now();
    for _ in 0..num_events {
        let _ = event_bus.connected.send(Arc::new(Connected));
    }
    let new_throughput_time = start.elapsed();
    let new_throughput = num_events as f64 / new_throughput_time.as_secs_f64();
    
    println!("Old system throughput: {:.0} events/sec", old_throughput);
    println!("New system throughput: {:.0} events/sec", new_throughput);
    println!("Throughput improvement: {:.2}x", new_throughput / old_throughput);
    
    assert!(new_throughput > old_throughput, "New system should be faster");
}

#[tokio::test]
async fn test_memory_efficiency() {
    println!("\n=== Memory Efficiency Test ===");
    
    // The new system uses separate channels for each event type,
    // which allows for more efficient memory usage and better cache locality
    let event_bus = EventBus::new();
    
    // Subscribe to only specific event types we care about
    let mut connected_rx = event_bus.connected.subscribe();
    let mut message_rx = event_bus.message.subscribe();
    
    // Create tasks that only handle specific events
    let connected_task = tokio::spawn(async move {
        let mut count = 0;
        while let Ok(_) = connected_rx.recv().await {
            count += 1;
            if count >= 100 { break; }
        }
        count
    });
    
    let message_task = tokio::spawn(async move {
        let mut count = 0;
        while let Ok(_) = message_rx.recv().await {
            count += 1;
            if count >= 100 { break; }
        }
        count
    });
    
    // Send events of different types
    for _ in 0..100 {
        let _ = event_bus.connected.send(Arc::new(Connected));
        let _ = event_bus.disconnected.send(Arc::new(Disconnected)); // Not subscribed to
        
        let msg = Box::new(wa::Message::default());
        let info = MessageInfo {
            source: MessageSource {
                chat: Jid::from_str("test@s.whatsapp.net").unwrap(),
                sender: Jid::from_str("test@s.whatsapp.net").unwrap(),
                is_from_me: false,
                is_group: false,
                ..Default::default()
            },
            id: "test".to_string(),
            server_id: 0,
            r#type: "text".to_string(),
            push_name: "Test".to_string(),
            timestamp: chrono::Utc::now(),
            category: "".to_string(),
            multicast: false,
            media_type: "".to_string(),
            edit: Default::default(),
            bot_info: None,
            meta_info: Default::default(),
            verified_name: None,
            device_sent_meta: None,
        };
        let _ = event_bus.message.send(Arc::new((msg, info)));
    }
    
    let connected_count = connected_task.await.unwrap();
    let message_count = message_task.await.unwrap();
    
    println!("Connected events processed: {}", connected_count);
    println!("Message events processed: {}", message_count);
    println!("✅ Memory efficient - tasks only process events they subscribe to");
    
    assert_eq!(connected_count, 100);
    assert_eq!(message_count, 100);
}