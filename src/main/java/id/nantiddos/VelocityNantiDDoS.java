package id.nantiddos;

import com.google.inject.Inject;
import com.velocitypowered.api.event.Subscribe;
import com.velocitypowered.api.event.connection.ConnectionHandshakeEvent;
import com.velocitypowered.api.event.connection.PreLoginEvent;
import com.velocitypowered.api.event.proxy.ProxyInitializeEvent;
import com.velocitypowered.api.event.proxy.ProxyShutdownEvent;
import com.velocitypowered.api.plugin.Plugin;
import com.velocitypowered.api.plugin.annotation.DataDirectory;
import com.velocitypowered.api.proxy.ProxyServer;
import org.slf4j.Logger;

import java.nio.file.Path;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.TimeUnit;

@Plugin(
    id = "nantiddos",
    name = "NantiDDoS",
    version = "1.0.0",
    description = "DDoS protection system for Velocity",
    authors = {"NusaPlugin"}
)
public class VelocityNantiDDoS {
    private final ProxyServer server;
    private final Logger logger;
    private final Path dataDirectory;
    
    private Set<String> blacklistedIps = new HashSet<>();
    private Map<String, ConnectionData> connectionTracker = new HashMap<>();
    private int maxConnectionsPerSecond = 3;
    private boolean enabled = true;

    @Inject
    public VelocityNantiDDoS(ProxyServer server, Logger logger, @DataDirectory Path dataDirectory) {
        this.server = server;
        this.logger = logger;
        this.dataDirectory = dataDirectory;
    }

    @Subscribe
    public void onProxyInitialization(ProxyInitializeEvent event) {
        logger.info("NantiDDoS for Velocity initializing...");
        // Initialize configuration
        loadConfiguration();
        
        // Schedule connection cleanup task
        server.getScheduler().buildTask(this, this::cleanupConnections)
            .delay(5, TimeUnit.MINUTES)
            .repeat(5, TimeUnit.MINUTES)
            .schedule();
            
        logger.info("NantiDDoS for Velocity initialized successfully!");
    }
    
    @Subscribe
    public void onProxyShutdown(ProxyShutdownEvent event) {
        // Save any data before shutdown
        logger.info("NantiDDoS for Velocity shutting down...");
    }
    
    @Subscribe
    public void onConnectionHandshake(ConnectionHandshakeEvent event) {
        if (!enabled) return;
        
        String ip = event.getConnection().getRemoteAddress().getAddress().getHostAddress();
        
        // Track connection
        ConnectionData data = connectionTracker.computeIfAbsent(ip, k -> new ConnectionData());
        data.incrementConnections();
        
        // Check if IP is blacklisted
        if (blacklistedIps.contains(ip)) {
            // Velocity doesn't allow canceling handshakes directly,
            // but we'll track this to deny in the PreLoginEvent
            data.blacklisted = true;
        }
    }
    
    @Subscribe
    public void onPreLogin(PreLoginEvent event) {
        if (!enabled) return;
        
        String ip = event.getConnection().getRemoteAddress().getAddress().getHostAddress();
        ConnectionData data = connectionTracker.get(ip);
        
        if (data != null) {
            // Check blacklist
            if (data.blacklisted) {
                event.setResult(PreLoginEvent.PreLoginComponentResult.denied(
                    net.kyori.adventure.text.Component.text("Your IP address is blacklisted from this server.")
                ));
                return;
            }
            
            // Check rate limiting
            if (data.connectionsPerSecond > maxConnectionsPerSecond) {
                event.setResult(PreLoginEvent.PreLoginComponentResult.denied(
                    net.kyori.adventure.text.Component.text("Connection throttled! Please wait before reconnecting.")
                ));
                logger.warn("Blocked connection attempt from {} (rate limit exceeded)", ip);
            }
        }
    }
    
    private void loadConfiguration() {
        // Load config file - simplified for this example
        maxConnectionsPerSecond = 3;  // Default value
        
        // In a real implementation, load from config file
    }
    
    private void cleanupConnections() {
        long currentTime = System.currentTimeMillis();
        connectionTracker.entrySet().removeIf(entry -> 
            currentTime - entry.getValue().lastConnectionTime > 60000);
    }
    
    private static class ConnectionData {
        private long firstConnectionTime;
        private long lastConnectionTime;
        private int connectionCount;
        private int connectionsPerSecond;
        private boolean blacklisted;
        
        public ConnectionData() {
            firstConnectionTime = System.currentTimeMillis();
            lastConnectionTime = firstConnectionTime;
            connectionCount = 0;
            connectionsPerSecond = 0;
        }
        
        public void incrementConnections() {
            connectionCount++;
            
            long currentTime = System.currentTimeMillis();
            if (currentTime - lastConnectionTime < 1000) {
                connectionsPerSecond++;
            } else {
                connectionsPerSecond = 1;
            }
            
            lastConnectionTime = currentTime;
        }
    }
}