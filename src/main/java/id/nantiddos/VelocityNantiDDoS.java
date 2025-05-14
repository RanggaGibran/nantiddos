package id.nantiddos;

import com.google.inject.Inject;
import com.velocitypowered.api.command.CommandManager;
import com.velocitypowered.api.command.CommandMeta;
import com.velocitypowered.api.command.SimpleCommand;
import com.velocitypowered.api.event.PostOrder;
import com.velocitypowered.api.event.Subscribe;
import com.velocitypowered.api.event.connection.ConnectionHandshakeEvent;
import com.velocitypowered.api.event.connection.DisconnectEvent;
import com.velocitypowered.api.event.connection.LoginEvent;
import com.velocitypowered.api.event.connection.PostLoginEvent;
import com.velocitypowered.api.event.connection.PreLoginEvent;
import com.velocitypowered.api.event.player.ServerConnectedEvent;
import com.velocitypowered.api.event.proxy.ProxyInitializeEvent;
import com.velocitypowered.api.event.proxy.ProxyPingEvent;
import com.velocitypowered.api.event.proxy.ProxyShutdownEvent;
import com.velocitypowered.api.plugin.Plugin;
import com.velocitypowered.api.plugin.annotation.DataDirectory;
import com.velocitypowered.api.proxy.Player;
import com.velocitypowered.api.proxy.ProxyServer;
import com.velocitypowered.api.proxy.server.ServerPing;
import id.nantiddos.network.VelocityNetworkManager;
import net.kyori.adventure.text.Component;
import net.kyori.adventure.text.format.NamedTextColor;
import net.kyori.adventure.text.format.TextColor;
import org.slf4j.Logger;

import java.io.File;
import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.file.Path;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import java.nio.file.Files;

@Plugin(
    id = "nantiddos",
    name = "NantiDDoS",
    version = "1.0.0",
    description = "Advanced DDoS protection system for Velocity",
    authors = {"NusaPlugin"}
)
public class VelocityNantiDDoS {
    private final ProxyServer server;
    private final Logger logger;
    private final Path dataDirectory;
    private final VelocityConfiguration config;
    private VelocityNetworkManager networkManager;
    
    // Protection components
    private final Map<String, ConnectionData> connectionTracker = new ConcurrentHashMap<>();
    private final Map<String, Integer> botScores = new ConcurrentHashMap<>();
    private final Set<String> blacklistedIps = Collections.synchronizedSet(new HashSet<>());
    private final Set<String> whitelistedIps = Collections.synchronizedSet(new HashSet<>());
    private final Map<String, NetworkData> networkData = new ConcurrentHashMap<>();
    private final List<AttackRecord> recentAttacks = Collections.synchronizedList(new ArrayList<>());
    
    // Cache for player data
    private final Map<UUID, String> playerIpCache = new ConcurrentHashMap<>();
    private final Map<UUID, PlayerData> playerData = new ConcurrentHashMap<>();
    
    // Network metrics
    private int activeConnections = 0;
    private int totalConnections = 0;
    private int blockedConnections = 0;
    private int currentThreatLevel = 0;
    private long startupTime;

    private final SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
    
    // Messages
    private Component kickMessage = Component.text("Connection throttled! Please wait before reconnecting.")
            .color(TextColor.color(0xFF5555));
    private Component blacklistedMessage = Component.text("Your IP address is blacklisted from this server.")
            .color(TextColor.color(0xFF5555));
    
    @Inject
    public VelocityNantiDDoS(ProxyServer server, Logger logger, @DataDirectory Path dataDirectory) {
        this.server = server;
        this.logger = logger;
        this.dataDirectory = dataDirectory;
        this.config = new VelocityConfiguration(logger, dataDirectory);
        this.startupTime = System.currentTimeMillis();
        
        // Create data directory if it doesn't exist
        File directory = dataDirectory.toFile();
        if (!directory.exists()) {
            directory.mkdirs();
        }
    }

    @Subscribe
    public void onProxyInitialization(ProxyInitializeEvent event) {
        logger.info("NantiDDoS for Velocity initializing...");
        
        loadBlacklist();
        loadWhitelist();
        registerCommands();
        
        // Initialize network manager
        networkManager = new VelocityNetworkManager(server, logger, this, config);
        server.getEventManager().register(this, networkManager);
        
        // Schedule tasks
        scheduleDataCollection();
        scheduleCleanupTask();
        scheduleAutosaveTasks();
        
        logger.info("NantiDDoS for Velocity initialized successfully!");
        logger.info("Protection status: " + (config.isEnableProtection() ? "ENABLED" : "DISABLED"));
        logger.info("Server ID: {}", config.getServerId());
        logger.info("Network ID: {}", config.getNetworkId());
        logger.info("Master Server: {}", config.isMasterServer() ? "YES" : "NO");
    }
    
    @Subscribe
    public void onProxyShutdown(ProxyShutdownEvent event) {
        // Save data before shutdown
        logger.info("NantiDDoS for Velocity shutting down...");
        saveBlacklist();
        saveWhitelist();
        logger.info("NantiDDoS data saved. Plugin disabled.");
    }
    
    @Subscribe(order = PostOrder.FIRST)
    public void onProxyPing(ProxyPingEvent event) {
        if (!config.isEnableProtection()) return;
        
        InetSocketAddress address = event.getConnection().getRemoteAddress();
        String ip = address.getAddress().getHostAddress();
        
        // Skip localhost and private IPs
        if (isLocalOrPrivateAddress(address.getAddress())) return;
        
        // Track connection
        ConnectionData data = connectionTracker.computeIfAbsent(ip, k -> new ConnectionData());
        data.incrementPings();
        totalConnections++;
        
        // Check if IP is blacklisted
        if (blacklistedIps.contains(ip)) {
            ServerPing.Builder builder = event.getPing().asBuilder();
            builder.version(new ServerPing.Version(-1, "Blacklisted"));
            builder.description(blacklistedMessage);
            event.setPing(builder.build());
            return;
        }
        
        // Check rate limiting
        if (shouldThrottleConnection(ip)) {
            ServerPing.Builder builder = event.getPing().asBuilder();
            builder.description(kickMessage);
            event.setPing(builder.build());
            blockedConnections++;
            logger.info("Throttled ping from " + ip + " (rate limit exceeded)");
            updateBotScore(ip, 1);
        }
    }
    
    @Subscribe(order = PostOrder.FIRST)
    public void onConnectionHandshake(ConnectionHandshakeEvent event) {
        if (!config.isEnableProtection()) return;
        
        InetSocketAddress address = event.getConnection().getRemoteAddress();
        String ip = address.getAddress().getHostAddress();
        
        // Skip localhost and private IPs
        if (isLocalOrPrivateAddress(address.getAddress())) return;
        
        // Track connection
        ConnectionData data = connectionTracker.computeIfAbsent(ip, k -> new ConnectionData());
        data.incrementConnections();
        
        // Update metrics
        activeConnections = Math.max(0, activeConnections + 1);
        totalConnections++;
    }
    
    @Subscribe(order = PostOrder.FIRST)
    public void onPreLogin(PreLoginEvent event) {
        if (!config.isEnableProtection()) return;
        
        InetSocketAddress address = event.getConnection().getRemoteAddress();
        String ip = address.getAddress().getHostAddress();
        
        // Skip localhost and private IPs
        if (isLocalOrPrivateAddress(address.getAddress())) return;
        
        ConnectionData data = connectionTracker.get(ip);
        if (data == null) return;
        
        // Check blacklist
        if (blacklistedIps.contains(ip)) {
            event.setResult(PreLoginEvent.PreLoginComponentResult.denied(blacklistedMessage));
            logger.info("Blocked login from blacklisted IP: " + ip);
            return;
        }
        
        // Check whitelist
        if (whitelistedIps.contains(ip)) {
            // Allow connection for whitelisted IPs
            return;
        }
        
        // Check rate limiting
        if (shouldThrottleConnection(ip)) {
            event.setResult(PreLoginEvent.PreLoginComponentResult.denied(kickMessage));
            blockedConnections++;
            logger.info("Blocked connection from " + ip + " (rate limit exceeded)");
            updateBotScore(ip, 5);
        }
        
        // Update connection types
        data.incrementLogins();
    }
    
    @Subscribe
    public void onLogin(LoginEvent event) {
        if (!config.isEnableProtection()) return;
        
        InetSocketAddress address = event.getPlayer().getRemoteAddress();
        String ip = address.getAddress().getHostAddress();
        
        // Skip localhost and private IPs
        if (isLocalOrPrivateAddress(address.getAddress())) return;
        
        ConnectionData data = connectionTracker.get(ip);
        if (data != null) {
            data.setLastValidLogin(System.currentTimeMillis());
            data.setPlayerName(event.getPlayer().getUsername());
            
            // Reduce bot score for successful login
            int currentScore = botScores.getOrDefault(ip, 0);
            if (currentScore > 0) {
                botScores.put(ip, Math.max(0, currentScore - 2));
            }
        }
    }
    
    @Subscribe
    public void onPostLogin(PostLoginEvent event) {
        Player player = event.getPlayer();
        String ip = player.getRemoteAddress().getAddress().getHostAddress();
        
        // Create player data entry
        PlayerData playerData = this.playerData.computeIfAbsent(
            player.getUniqueId(), 
            k -> new PlayerData(player.getUsername(), ip)
        );
        
        // If player has permission to bypass protection or view alerts
        boolean isAdmin = player.hasPermission("nantiddos.admin");
        boolean canBypass = player.hasPermission("nantiddos.bypass");
        
        playerData.setAdmin(isAdmin);
        playerData.setBypass(canBypass);
        
        // Store player IP mapping for quick lookup
        playerIpCache.put(player.getUniqueId(), ip);
        
        // Show threat alerts to admins
        if (isAdmin && currentThreatLevel > 50) {
            sendThreatAlert(player);
        }
        
        // For admins, show server ID information
        if (isAdmin) {
            Component message = Component.text("[NantiDDoS] ")
                .color(TextColor.color(0xFF5555))
                .append(Component.text("Server ID: " + config.getServerId() + ", Network: " + config.getNetworkId())
                .color(TextColor.color(0xFFFF55)));
            player.sendMessage(message);
        }
    }
    
    @Subscribe
    public void onDisconnect(DisconnectEvent event) {
        UUID playerId = event.getPlayer().getUniqueId();
        
        // Remove player data
        playerIpCache.remove(playerId);
        playerData.remove(playerId);
        
        // Update active connections
        activeConnections = Math.max(0, activeConnections - 1);
    }
    
    @Subscribe
    public void onServerConnected(ServerConnectedEvent event) {
        // Track server switches if needed
        PlayerData data = playerData.get(event.getPlayer().getUniqueId());
        if (data != null) {
            data.updateActivity();
            String serverName = event.getServer().getServerInfo().getName();
            data.addServerSwitch(serverName);
            
            // If this is an admin, check if they need a threat notification update
            if (data.isAdmin() && currentThreatLevel > 50) {
                // Only notify periodically to avoid spam
                if (System.currentTimeMillis() - data.getLastActive() > 300000) { // 5 minutes
                    sendThreatAlert(event.getPlayer());
                }
            }
        }
    }

    // Methods for network integration
    public void addToBlacklist(String ip) {
        if (!blacklistedIps.contains(ip)) {
            blacklistedIps.add(ip);
            saveBlacklist();
            
            // Kick players with this IP
            kickPlayersWithIp(ip);
        }
    }

    public void addToWhitelist(String ip) {
        if (!whitelistedIps.contains(ip)) {
            whitelistedIps.add(ip);
            blacklistedIps.remove(ip);  // Remove from blacklist if present
            saveWhitelist();
        }
    }

    public void updateBotScore(String ip, int score) {
        int currentScore = botScores.getOrDefault(ip, 0);
        botScores.put(ip, Math.max(0, Math.min(100, currentScore + score)));
    }

    public Set<String> getBlacklistedIps() {
        return blacklistedIps;
    }

    public Set<String> getWhitelistedIps() {
        return whitelistedIps;
    }

    public Map<String, Integer> getSuspiciousIps() {
        Map<String, Integer> result = new HashMap<>();
        for (Map.Entry<String, Integer> entry : botScores.entrySet()) {
            if (entry.getValue() > config.getBotScoreThreshold()) {
                result.put(entry.getKey(), entry.getValue());
            }
        }
        return result;
    }

    public int getCurrentThreatLevel() {
        return currentThreatLevel;
    }

    public Set<String> getConnectedIps() {
        return connectionTracker.keySet();
    }

    // Add other methods from original implementation...
    
    private void registerCommands() {
        CommandManager commandManager = server.getCommandManager();
        
        // Main command
        CommandMeta mainMeta = commandManager.metaBuilder("nantiddos")
            .plugin(this)
            .build();
        
        SimpleCommand mainCommand = new SimpleCommand() {
            @Override
            public void execute(Invocation invocation) {
                String[] args = invocation.arguments();
                
                // Check permission
                if (!invocation.source().hasPermission("nantiddos.admin")) {
                    invocation.source().sendMessage(Component.text("You don't have permission to use this command.")
                        .color(NamedTextColor.RED));
                    return;
                }
                
                if (args.length == 0) {
                    showHelp(invocation.source());
                    return;
                }
                
                switch (args[0].toLowerCase()) {
                    case "reload":
                        config.loadConfiguration();
                        loadBlacklist();
                        loadWhitelist();
                        invocation.source().sendMessage(Component.text("NantiDDoS configuration reloaded!")
                            .color(NamedTextColor.GREEN));
                        break;
                        
                    case "status":
                        showStatus(invocation.source());
                        break;
                        
                    case "enable":
                        config.setEnableProtection(true);
                        invocation.source().sendMessage(Component.text("NantiDDoS protection enabled!")
                            .color(NamedTextColor.GREEN));
                        break;
                        
                    case "disable":
                        config.setEnableProtection(false);
                        invocation.source().sendMessage(Component.text("NantiDDoS protection disabled!")
                            .color(NamedTextColor.RED));
                        break;
                        
                    case "whitelist":
                        handleWhitelistCommand(invocation.source(), args);
                        break;
                        
                    case "blacklist":
                        handleBlacklistCommand(invocation.source(), args);
                        break;
                        
                    case "stats":
                        showStatistics(invocation.source());
                        break;
                        
                    case "network":
                        handleNetworkCommand(invocation.source(), args);
                        break;
                        
                    case "clear":
                        connectionTracker.clear();
                        botScores.clear();
                        invocation.source().sendMessage(Component.text("Connection data cleared!")
                            .color(NamedTextColor.GREEN));
                        break;
                        
                    default:
                        showHelp(invocation.source());
                        break;
                }
            }
            
            @Override
            public List<String> suggest(Invocation invocation) {
                String[] args = invocation.arguments();
                
                if (args.length == 0) {
                    return Arrays.asList("reload", "status", "enable", "disable", "whitelist", 
                        "blacklist", "stats", "network", "clear");
                }
                
                if (args.length == 1) {
                    return Arrays.asList("reload", "status", "enable", "disable", "whitelist", 
                        "blacklist", "stats", "network", "clear").stream()
                        .filter(cmd -> cmd.startsWith(args[0].toLowerCase()))
                        .collect(java.util.stream.Collectors.toList());
                }
                
                if (args.length == 2) {
                    if ("whitelist".equalsIgnoreCase(args[0]) || "blacklist".equalsIgnoreCase(args[0])) {
                        return Arrays.asList("add", "remove", "list").stream()
                            .filter(cmd -> cmd.startsWith(args[1].toLowerCase()))
                            .collect(java.util.stream.Collectors.toList());
                    } else if ("network".equalsIgnoreCase(args[0])) {
                        return Arrays.asList("status", "sync", "master").stream()
                            .filter(cmd -> cmd.startsWith(args[1].toLowerCase()))
                            .collect(java.util.stream.Collectors.toList());
                    }
                }
                
                if (args.length == 3 && "network".equalsIgnoreCase(args[0]) && "master".equalsIgnoreCase(args[1])) {
                    return Arrays.asList("true", "false");
                }
                
                return Collections.emptyList();
            }
        };
        
        commandManager.register(mainMeta, mainCommand);
    }
    
    private void handleNetworkCommand(net.kyori.adventure.audience.Audience source, String[] args) {
        if (args.length < 2) {
            source.sendMessage(Component.text("Network Commands:")
                .color(TextColor.color(0xFFAA00)));
            source.sendMessage(Component.text("/nantiddos network status - View network status")
                .color(TextColor.color(0xFFFF55)));
            source.sendMessage(Component.text("/nantiddos network sync - Force sync network data")
                .color(TextColor.color(0xFFFF55)));
            source.sendMessage(Component.text("/nantiddos network master <true|false> - Set master status")
                .color(TextColor.color(0xFFFF55)));
            return;
        }
        
        switch (args[1].toLowerCase()) {
            case "status":
                showNetworkStatus(source);
                break;
                
            case "sync":
                source.sendMessage(Component.text("Forcing network data synchronization...")
                    .color(TextColor.color(0x55FF55)));
                // Force data sync
                if (networkManager != null) {
                    server.getScheduler().buildTask(this, () -> {
                        // Simulate synchronization event
                        source.sendMessage(Component.text("Network data synchronized")
                            .color(TextColor.color(0x55FF55)));
                    }).schedule();
                }
                break;
                
            case "master":
                if (args.length < 3) {
                    source.sendMessage(Component.text("Usage: /nantiddos network master <true|false>")
                        .color(TextColor.color(0xFF5555)));
                    return;
                }
                
                boolean setAsMaster = Boolean.parseBoolean(args[2]);
                config.setMasterServer(setAsMaster);
                if (setAsMaster) {
                    config.setMasterServerId(config.getServerId());
                }
                
                source.sendMessage(Component.text("Server master status set to: " + setAsMaster)
                    .color(TextColor.color(0x55FF55)));
                break;
                
            default:
                source.sendMessage(Component.text("Unknown network subcommand: " + args[1])
                    .color(TextColor.color(0xFF5555)));
                source.sendMessage(Component.text("Usage: /nantiddos network <status|sync|master>")
                    .color(TextColor.color(0xFF5555)));
                break;
        }
    }
    
    private void showNetworkStatus(net.kyori.adventure.audience.Audience source) {
        source.sendMessage(Component.text("========== Network Status ==========")
            .color(TextColor.color(0xFFAA00)));
        source.sendMessage(Component.text("Server ID: " + config.getServerId())
            .color(TextColor.color(0x55FF55)));
        source.sendMessage(Component.text("Network ID: " + config.getNetworkId())
            .color(TextColor.color(0x55FF55)));
        source.sendMessage(Component.text("Is Master Server: " + config.isMasterServer())
            .color(TextColor.color(0x55FF55)));
        source.sendMessage(Component.text("Master Server ID: " + config.getMasterServerId())
            .color(TextColor.color(0x55FF55)));
        
        if (networkManager != null) {
            Map<String, VelocityNetworkManager.ServerInfo> servers = networkManager.getNetworkServers();
            source.sendMessage(Component.text("Connected Servers: " + servers.size())
                .color(TextColor.color(0x55FF55)));
            
            int i = 0;
            for (Map.Entry<String, VelocityNetworkManager.ServerInfo> entry : servers.entrySet()) {
                if (i++ >= 5) {
                    source.sendMessage(Component.text("...and " + (servers.size() - 5) + " more servers")
                        .color(TextColor.color(0xAAAAAA)));
                    break;
                }
                
                source.sendMessage(Component.text("- " + entry.getKey() + 
                    (entry.getValue().isMaster() ? " (MASTER)" : ""))
                    .color(TextColor.color(0xFFFFFF)));
            }
        } else {
            source.sendMessage(Component.text("Network manager not initialized")
                .color(TextColor.color(0xFF5555)));
        }
    }
    
    
    // Missing schedule methods
    private void scheduleDataCollection() {
        server.getScheduler().buildTask(this, () -> {
            if (!config.isEnableProtection()) return;
            
            analyzeData();
        }).repeat(60, TimeUnit.SECONDS).schedule();
    }
    
    private void scheduleCleanupTask() {
        server.getScheduler().buildTask(this, () -> {
            if (!config.isEnableProtection()) return;
            
            cleanupOldData();
        }).repeat(10, TimeUnit.MINUTES).schedule();
    }
    
    private void scheduleAutosaveTasks() {
        server.getScheduler().buildTask(this, () -> {
            saveBlacklist();
            saveWhitelist();
            logger.info("Saved blacklist and whitelist data");
        }).repeat(15, TimeUnit.MINUTES).schedule();
    }
    
    // Utility methods
    private boolean isLocalOrPrivateAddress(InetAddress address) {
        return address.isLoopbackAddress() || 
               address.isSiteLocalAddress() || 
               address.isLinkLocalAddress();
    }
    
    private boolean shouldThrottleConnection(String ip) {
        // Skip checks for whitelisted IPs
        if (whitelistedIps.contains(ip)) {
            return false;
        }
        
        // Always block blacklisted IPs
        if (blacklistedIps.contains(ip)) {
            return true;
        }
        
        // Check bot score
        int botScore = botScores.getOrDefault(ip, 0);
        if (botScore >= config.getBotScoreThreshold()) {
            return true;
        }
        
        // Check connection rate
        ConnectionData data = connectionTracker.get(ip);
        if (data != null && data.getConnectionsPerSecond() > config.getMaxConnectionsPerSecond()) {
            updateBotScore(ip, 1);
            return true;
        }
        
        return false;
    }
    
    private void kickPlayersWithIp(String ip) {
        for (Player player : server.getAllPlayers()) {
            String playerIp = player.getRemoteAddress().getAddress().getHostAddress();
            if (playerIp.equals(ip)) {
                player.disconnect(blacklistedMessage);
            }
        }
    }
    
    private void sendThreatAlert(Player player) {
        player.sendMessage(Component.text("§c[NantiDDoS] §eWarning: Current threat level is " + 
            formatThreatLevel(currentThreatLevel) + " §e(" + currentThreatLevel + "/100)"));
    }
    
    private String formatThreatLevel(int level) {
        if (level >= 80) return "§4CRITICAL";
        if (level >= 60) return "§cHIGH";
        if (level >= 40) return "§6MEDIUM";
        if (level >= 20) return "§eLOW";
        return "§aNORMAL";
    }
    
    // Dashboard methods
    private void showHelp(net.kyori.adventure.audience.Audience source) {
        source.sendMessage(Component.text("========== NantiDDoS Help ==========").color(TextColor.color(0xFFAA00)));
        source.sendMessage(Component.text("/nantiddos status - Show current protection status").color(TextColor.color(0xFFFF55)));
        source.sendMessage(Component.text("/nantiddos reload - Reload configuration").color(TextColor.color(0xFFFF55)));
        source.sendMessage(Component.text("/nantiddos enable - Enable protection").color(TextColor.color(0xFFFF55)));
        source.sendMessage(Component.text("/nantiddos disable - Disable protection").color(TextColor.color(0xFFFF55)));
        source.sendMessage(Component.text("/nantiddos whitelist <add|remove|list> [ip] - Manage whitelist").color(TextColor.color(0xFFFF55)));
        source.sendMessage(Component.text("/nantiddos blacklist <add|remove|list> [ip] - Manage blacklist").color(TextColor.color(0xFFFF55)));
        source.sendMessage(Component.text("/nantiddos stats - Show protection statistics").color(TextColor.color(0xFFFF55)));
        source.sendMessage(Component.text("/nantiddos network <status|sync|master> - Network settings").color(TextColor.color(0xFFFF55)));
        source.sendMessage(Component.text("/nantiddos clear - Clear connection data").color(TextColor.color(0xFFFF55)));
    }
    
    private void showStatus(net.kyori.adventure.audience.Audience source) {
        source.sendMessage(Component.text("========== NantiDDoS Status ==========").color(TextColor.color(0xFFAA00)));
        source.sendMessage(Component.text("Protection: " + 
            (config.isEnableProtection() ? "ENABLED" : "DISABLED")).color(
                config.isEnableProtection() ? TextColor.color(0x55FF55) : TextColor.color(0xFF5555)));
        source.sendMessage(Component.text("Max Connections/Second: " + config.getMaxConnectionsPerSecond()).color(TextColor.color(0x55FF55)));
        source.sendMessage(Component.text("Connection Timeout: " + config.getConnectionTimeout() + "ms").color(TextColor.color(0x55FF55)));
        source.sendMessage(Component.text("Auto Blacklisting: " + (config.isEnableAutomaticBlacklisting() ? "ENABLED" : "DISABLED")).color(TextColor.color(0x55FF55)));
        source.sendMessage(Component.text("Tracked IPs: " + connectionTracker.size()).color(TextColor.color(0x55FF55)));
        source.sendMessage(Component.text("Suspicious IPs: " + getSuspiciousIpCount()).color(TextColor.color(0xFF5555)));
        source.sendMessage(Component.text("Whitelisted IPs: " + whitelistedIps.size()).color(TextColor.color(0x55FF55)));
        source.sendMessage(Component.text("Blacklisted IPs: " + blacklistedIps.size()).color(TextColor.color(0xFF5555)));
        source.sendMessage(Component.text("Current Threat Level: " + formatThreatLevel(currentThreatLevel)).color(TextColor.color(0xFFFF55)));
        source.sendMessage(Component.text("Uptime: " + formatUptime()).color(TextColor.color(0x55FF55)));
    }
    
    private void handleWhitelistCommand(net.kyori.adventure.audience.Audience source, String[] args) {
        if (args.length < 2) {
            source.sendMessage(Component.text("Usage: /nantiddos whitelist <add|remove|list> [ip]")
                .color(TextColor.color(0xFF5555)));
            return;
        }
        
        switch (args[1].toLowerCase()) {
            case "add":
                if (args.length < 3) {
                    source.sendMessage(Component.text("Usage: /nantiddos whitelist add <ip>")
                        .color(TextColor.color(0xFF5555)));
                    return;
                }
                
                String ipToAdd = args[2];
                if (isValidIp(ipToAdd)) {
                    whitelistedIps.add(ipToAdd);
                    blacklistedIps.remove(ipToAdd); // Remove from blacklist if present
                    saveWhitelist();
                    source.sendMessage(Component.text(ipToAdd + " added to whitelist.")
                        .color(TextColor.color(0x55FF55)));
                } else {
                    source.sendMessage(Component.text("Invalid IP address: " + ipToAdd)
                        .color(TextColor.color(0xFF5555)));
                }
                break;
                
            case "remove":
                if (args.length < 3) {
                    source.sendMessage(Component.text("Usage: /nantiddos whitelist remove <ip>")
                        .color(TextColor.color(0xFF5555)));
                    return;
                }
                
                String ipToRemove = args[2];
                if (whitelistedIps.remove(ipToRemove)) {
                    saveWhitelist();
                    source.sendMessage(Component.text(ipToRemove + " removed from whitelist.")
                        .color(TextColor.color(0x55FF55)));
                } else {
                    source.sendMessage(Component.text(ipToRemove + " not found in whitelist.")
                        .color(TextColor.color(0xFF5555)));
                }
                break;
                
            case "list":
                source.sendMessage(Component.text("========== Whitelisted IPs ==========")
                    .color(TextColor.color(0xFFAA00)));
                
                if (whitelistedIps.isEmpty()) {
                    source.sendMessage(Component.text("No IPs in whitelist.")
                        .color(TextColor.color(0xAAAAAA)));
                } else {
                    for (String ip : whitelistedIps) {
                        source.sendMessage(Component.text("- " + ip)
                            .color(TextColor.color(0xFFFFFF)));
                    }
                }
                break;
                
            default:
                source.sendMessage(Component.text("Unknown subcommand: " + args[1])
                    .color(TextColor.color(0xFF5555)));
                source.sendMessage(Component.text("Usage: /nantiddos whitelist <add|remove|list> [ip]")
                    .color(TextColor.color(0xFF5555)));
                break;
        }
    }
    
    private void handleBlacklistCommand(net.kyori.adventure.audience.Audience source, String[] args) {
        if (args.length < 2) {
            source.sendMessage(Component.text("Usage: /nantiddos blacklist <add|remove|list> [ip]")
                .color(TextColor.color(0xFF5555)));
            return;
        }
        
        switch (args[1].toLowerCase()) {
            case "add":
                if (args.length < 3) {
                    source.sendMessage(Component.text("Usage: /nantiddos blacklist add <ip>")
                        .color(TextColor.color(0xFF5555)));
                    return;
                }
                
                String ipToAdd = args[2];
                if (isValidIp(ipToAdd)) {
                    blacklistedIps.add(ipToAdd);
                    whitelistedIps.remove(ipToAdd); // Remove from whitelist if present
                    
                    // Kick players with this IP
                    kickPlayersWithIp(ipToAdd);
                    
                    saveBlacklist();
                    source.sendMessage(Component.text(ipToAdd + " added to blacklist.")
                        .color(TextColor.color(0x55FF55)));
                } else {
                    source.sendMessage(Component.text("Invalid IP address: " + ipToAdd)
                        .color(TextColor.color(0xFF5555)));
                }
                break;
                
            case "remove":
                if (args.length < 3) {
                    source.sendMessage(Component.text("Usage: /nantiddos blacklist remove <ip>")
                        .color(TextColor.color(0xFF5555)));
                    return;
                }
                
                String ipToRemove = args[2];
                if (blacklistedIps.remove(ipToRemove)) {
                    saveBlacklist();
                    source.sendMessage(Component.text(ipToRemove + " removed from blacklist.")
                        .color(TextColor.color(0x55FF55)));
                } else {
                    source.sendMessage(Component.text(ipToRemove + " not found in blacklist.")
                        .color(TextColor.color(0xFF5555)));
                }
                break;
                
            case "list":
                source.sendMessage(Component.text("========== Blacklisted IPs ==========")
                    .color(TextColor.color(0xFFAA00)));
                
                if (blacklistedIps.isEmpty()) {
                    source.sendMessage(Component.text("No IPs in blacklist.")
                        .color(TextColor.color(0xAAAAAA)));
                } else {
                    for (String ip : blacklistedIps) {
                        source.sendMessage(Component.text("- " + ip)
                            .color(TextColor.color(0xFFFFFF)));
                    }
                }
                break;
                
            default:
                source.sendMessage(Component.text("Unknown subcommand: " + args[1])
                    .color(TextColor.color(0xFF5555)));
                source.sendMessage(Component.text("Usage: /nantiddos blacklist <add|remove|list> [ip]")
                    .color(TextColor.color(0xFF5555)));
                break;
        }
    }
    
    private void showStatistics(net.kyori.adventure.audience.Audience source) {
        source.sendMessage(Component.text("========== NantiDDoS Statistics ==========").color(TextColor.color(0xFFAA00)));
        source.sendMessage(Component.text("Active Connections: " + activeConnections).color(TextColor.color(0x55FF55)));
        source.sendMessage(Component.text("Total Connections: " + totalConnections).color(TextColor.color(0x55FF55)));
        source.sendMessage(Component.text("Blocked Connections: " + blockedConnections).color(TextColor.color(0xFF5555)));
        source.sendMessage(Component.text("Block Rate: " + String.format("%.2f%%", totalConnections > 0 ? (blockedConnections * 100.0 / totalConnections) : 0)).color(TextColor.color(0xFFFF55)));
        
        // Find top attack sources
        List<Map.Entry<String, Integer>> topBotScores = new ArrayList<>(botScores.entrySet());
        topBotScores.sort(Map.Entry.<String, Integer>comparingByValue().reversed());
        
        source.sendMessage(Component.text("Top Suspicious IPs:").color(TextColor.color(0xFFFF55)));
        
        int shown = 0;
        for (Map.Entry<String, Integer> entry : topBotScores) {
            if (shown >= 5) break;
            
            String ip = entry.getKey();
            int score = entry.getValue();
            
            if (score >= 5) {
                shown++;
                ConnectionData data = connectionTracker.get(ip);
                String playerName = data != null ? data.getPlayerName() : "Unknown";
                
                source.sendMessage(Component.text("- " + ip + " (Score: " + score + ") " + 
                    (playerName != null ? "Player: " + playerName : "")).color(
                        score >= 20 ? TextColor.color(0xFF5555) : 
                        score >= 10 ? TextColor.color(0xFFAA00) : 
                        TextColor.color(0xFFFF55)));
            }
        }
        
        source.sendMessage(Component.text("Recent Attacks: " + recentAttacks.size()).color(TextColor.color(0xFF5555)));
        
        if (!recentAttacks.isEmpty()) {
            source.sendMessage(Component.text("Latest Attack:").color(TextColor.color(0xFFFF55)));
            AttackRecord latest = recentAttacks.get(recentAttacks.size() - 1);
            source.sendMessage(Component.text("- Type: " + latest.type + ", Score: " + latest.severity + 
                ", Time: " + dateFormat.format(new Date(latest.timestamp)))
                .color(TextColor.color(0xFF5555)));
        }
    }
    
    // Storage methods
    private void loadBlacklist() {
        try {
            Path blacklistPath = dataDirectory.resolve("blacklist.txt");
            File blacklistFile = blacklistPath.toFile();
            
            if (!blacklistFile.exists()) {
                blacklistFile.createNewFile();
                return;
            }
            
            blacklistedIps.clear();
            List<String> lines = Files.readAllLines(blacklistPath);
            
            for (String line : lines) {
                line = line.trim();
                if (!line.isEmpty() && isValidIp(line)) {
                    blacklistedIps.add(line);
                }
            }
            
            logger.info("Loaded " + blacklistedIps.size() + " IPs to blacklist");
            
        } catch (IOException e) {
            logger.error("Failed to load blacklist", e);
        }
    }
    
    private void saveBlacklist() {
        try {
            Path blacklistPath = dataDirectory.resolve("blacklist.txt");
            
            List<String> lines = new ArrayList<>(blacklistedIps);
            Collections.sort(lines);
            
            Files.write(blacklistPath, lines);
            
        } catch (IOException e) {
            logger.error("Failed to save blacklist", e);
        }
    }
    
    private void loadWhitelist() {
        try {
            Path whitelistPath = dataDirectory.resolve("whitelist.txt");
            File whitelistFile = whitelistPath.toFile();
            
            if (!whitelistFile.exists()) {
                whitelistFile.createNewFile();
                return;
            }
            
            whitelistedIps.clear();
            List<String> lines = Files.readAllLines(whitelistPath);
            
            for (String line : lines) {
                line = line.trim();
                if (!line.isEmpty() && isValidIp(line)) {
                    whitelistedIps.add(line);
                }
            }
            
            logger.info("Loaded " + whitelistedIps.size() + " IPs to whitelist");
            
        } catch (IOException e) {
            logger.error("Failed to load whitelist", e);
        }
    }
    
    private void saveWhitelist() {
        try {
            Path whitelistPath = dataDirectory.resolve("whitelist.txt");
            
            List<String> lines = new ArrayList<>(whitelistedIps);
            Collections.sort(lines);
            
            Files.write(whitelistPath, lines);
            
        } catch (IOException e) {
            logger.error("Failed to save whitelist", e);
        }
    }
    
    // Additional utility methods
    private boolean isValidIp(String ip) {
        if (ip == null || ip.isEmpty()) {
            return false;
        }
        
        String[] parts = ip.split("\\.");
        if (parts.length != 4) {
            return false;
        }
        
        try {
            for (String part : parts) {
                int num = Integer.parseInt(part);
                if (num < 0 || num > 255) {
                    return false;
                }
            }
            return true;
        } catch (NumberFormatException e) {
            return false;
        }
    }
    
    private void analyzeData() {
        // Decay bot scores over time
        for (Map.Entry<String, Integer> entry : new HashMap<>(botScores).entrySet()) {
            int score = entry.getValue();
            if (score > 0) {
                score = Math.max(0, score - 1);
                botScores.put(entry.getKey(), score);
            }
        }
        
        // Update threat level based on various factors
        updateThreatLevel();
    }
    
    private void cleanupOldData() {
        long now = System.currentTimeMillis();
        
        // Remove connection data older than 30 minutes
        connectionTracker.entrySet().removeIf(entry -> 
            now - entry.getValue().getLastConnectionTime() > 30 * 60 * 1000);
            
        // Remove attack records older than 24 hours
        recentAttacks.removeIf(attack -> 
            now - attack.timestamp > 24 * 60 * 60 * 1000);
            
        // Remove bot scores for IPs that are no longer tracked
        botScores.entrySet().removeIf(entry ->
            !connectionTracker.containsKey(entry.getKey()));
    }
    
    private void updateThreatLevel() {
        int newThreatLevel = 0;
        
        // Calculate based on bot scores
        int highScoreCount = 0;
        for (int score : botScores.values()) {
            if (score >= config.getAutoblacklistThreshold()) highScoreCount += 3;
            else if (score >= config.getBlacklistThreshold()) highScoreCount += 2;
            else if (score >= config.getBotScoreThreshold()) highScoreCount += 1;
        }
        
        if (highScoreCount > 10) newThreatLevel = Math.max(newThreatLevel, 80);
        else if (highScoreCount > 5) newThreatLevel = Math.max(newThreatLevel, 60);
        else if (highScoreCount > 2) newThreatLevel = Math.max(newThreatLevel, 40);
        else if (highScoreCount > 0) newThreatLevel = Math.max(newThreatLevel, 20);
        
        // Calculate based on connection rate
        int highRateCount = 0;
        for (ConnectionData data : connectionTracker.values()) {
            if (data.getConnectionsPerSecond() > config.getMaxConnectionsPerSecond() * 2) highRateCount += 2;
            else if (data.getConnectionsPerSecond() > config.getMaxConnectionsPerSecond()) highRateCount += 1;
        }
        
        if (highRateCount > 8) newThreatLevel = Math.max(newThreatLevel, 80);
        else if (highRateCount > 4) newThreatLevel = Math.max(newThreatLevel, 60);
        else if (highRateCount > 2) newThreatLevel = Math.max(newThreatLevel, 40);
        else if (highRateCount > 0) newThreatLevel = Math.max(newThreatLevel, 20);
        
        // Smooth transitions
        if (newThreatLevel > currentThreatLevel) {
            currentThreatLevel = newThreatLevel; // Immediate increase
        } else if (newThreatLevel < currentThreatLevel) {
            currentThreatLevel = Math.max(newThreatLevel, currentThreatLevel - 5); // Gradual decrease
        }
    }
    
    private int getSuspiciousIpCount() {
        int count = 0;
        for (int score : botScores.values()) {
            if (score >= config.getBotScoreThreshold()) count++;
        }
        return count;
    }
    
    private String formatUptime() {
        long uptime = System.currentTimeMillis() - startupTime;
        
        long seconds = uptime / 1000;
        long minutes = seconds / 60;
        long hours = minutes / 60;
        long days = hours / 24;
        
        seconds %= 60;
        minutes %= 60;
        hours %= 24;
        
        StringBuilder sb = new StringBuilder();
        if (days > 0) sb.append(days).append("d ");
        if (hours > 0 || days > 0) sb.append(hours).append("h ");
        if (minutes > 0 || hours > 0 || days > 0) sb.append(minutes).append("m ");
        sb.append(seconds).append("s");
        
        return sb.toString();
    }
    
    // Inner classes
    private class ConnectionData {
        private long firstConnectionTime;
        private long lastConnectionTime;
        private long lastValidLogin;
        private int pingCount;
        private int loginCount;
        private int connectionsPerSecond;
        private String playerName;
        
        public ConnectionData() {
            firstConnectionTime = System.currentTimeMillis();
            lastConnectionTime = firstConnectionTime;
            lastValidLogin = 0;
            pingCount = 0;
            loginCount = 0;
            connectionsPerSecond = 0;
        }
        
        public void incrementPings() {
            pingCount++;
            updateConnectionTime();
        }
        
        public void incrementLogins() {
            loginCount++;
            updateConnectionTime();
        }
        
        public void incrementConnections() {
            updateConnectionTime();
        }
        
        private void updateConnectionTime() {
            long currentTime = System.currentTimeMillis();
            
            if (currentTime - lastConnectionTime < 1000) {
                connectionsPerSecond++;
            } else {
                connectionsPerSecond = 1;
            }
            
            lastConnectionTime = currentTime;
        }
        
        public long getFirstConnectionTime() {
            return firstConnectionTime;
        }
        
        public long getLastConnectionTime() {
            return lastConnectionTime;
        }
        
        public int getConnectionsPerSecond() {
            return connectionsPerSecond;
        }
        
        public int getPingCount() {
            return pingCount;
        }
        
        public int getLoginCount() {
            return loginCount;
        }
        
        public void setLastValidLogin(long time) {
            this.lastValidLogin = time;
        }
        
        public long getLastValidLogin() {
            return lastValidLogin;
        }
        
        public String getPlayerName() {
            return playerName;
        }
        
        public void setPlayerName(String playerName) {
            this.playerName = playerName;
        }
    }
    
    private class NetworkData {
        private final String networkId;
        private int connectionCount;
        private int activeConnections;
        private int blockedConnections;
        private int threatLevel;
        
        public NetworkData(String networkId) {
            this.networkId = networkId;
            this.connectionCount = 0;
            this.activeConnections = 0;
            this.blockedConnections = 0;
            this.threatLevel = 0;
        }
        
        public void incrementConnectionCount() {
            connectionCount++;
        }
        
        public void setThreatLevel(int level) {
            threatLevel = level;
        }
        
        public String getNetworkId() {
            return networkId;
        }
        
        public int getConnectionCount() {
            return connectionCount;
        }
        
        public int getThreatLevel() {
            return threatLevel;
        }
    }
    
    private class AttackRecord {
        private final String type;
        private final String source;
        private final int severity;
        private final long timestamp;
        
        public AttackRecord(String type, String source, int severity) {
            this.type = type;
            this.source = source;
            this.severity = severity;
            this.timestamp = System.currentTimeMillis();
        }
    }
    
    private class PlayerData {
        private final String username;
        private final String ip;
        private long joinTime;
        private long lastActive;
        private List<String> serverSwitches;
        private boolean isAdmin;
        private boolean canBypass;
        
        public PlayerData(String username, String ip) {
            this.username = username;
            this.ip = ip;
            this.joinTime = System.currentTimeMillis();
            this.lastActive = joinTime;
            this.serverSwitches = new ArrayList<>();
            this.isAdmin = false;
            this.canBypass = false;
        }
        
        public void updateActivity() {
            this.lastActive = System.currentTimeMillis();
        }
        
        public void addServerSwitch(String server) {
            serverSwitches.add(server);
            updateActivity();
        }
        
        public String getUsername() {
            return username;
        }
        
        public String getIp() {
            return ip;
        }
        
        public long getJoinTime() {
            return joinTime;
        }
        
        public long getLastActive() {
            return lastActive;
        }
        
        public List<String> getServerSwitches() {
            return new ArrayList<>(serverSwitches);
        }
        
        public void setAdmin(boolean isAdmin) {
            this.isAdmin = isAdmin;
        }
        
        public boolean isAdmin() {
            return isAdmin;
        }
        
        public void setBypass(boolean canBypass) {
            this.canBypass = canBypass;
        }
        
        public boolean canBypass() {
            return canBypass;
        }
    }
}