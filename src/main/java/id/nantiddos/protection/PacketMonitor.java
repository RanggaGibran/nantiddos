package id.nantiddos.protection;

import id.nantiddos.Nantiddos;

import java.net.InetAddress;
import java.util.EnumMap;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import java.util.logging.Logger;

import org.bukkit.Bukkit;
import org.bukkit.entity.Player;
import org.bukkit.event.EventHandler;
import org.bukkit.event.EventPriority;
import org.bukkit.event.Listener;
import org.bukkit.event.player.PlayerJoinEvent;
import org.bukkit.event.player.PlayerQuitEvent;
import org.bukkit.plugin.Plugin;
import org.bukkit.scheduler.BukkitTask;

public class PacketMonitor implements Listener {
    private final Nantiddos plugin;
    private final Logger logger;
    private final ConnectionTracker connectionTracker;
    private final IPManager ipManager;
    
    private BukkitTask analysisTask;
    private boolean protocolLibAvailable;
    private boolean enabled = true;
    
    private final ConcurrentHashMap<UUID, PlayerPacketData> packetDataMap = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, IpPacketStatistics> ipStatisticsMap = new ConcurrentHashMap<>();
    
    private int packetLimitThreshold;
    private int packetAnalysisInterval;
    private int suspiciousPacketThreshold;
    private int autobanThreshold;
    private boolean autobanEnabled;
    private boolean intelligentFiltering;
    
    public enum PacketCategory {
        MOVEMENT, INTERACTION, INVENTORY, CHAT, OTHER
    }
    
    public enum ThreatLevel {
        NONE(0), LOW(1), MEDIUM(2), HIGH(3), CRITICAL(4);
        
        private final int level;
        
        ThreatLevel(int level) {
            this.level = level;
        }
        
        public int getLevel() {
            return level;
        }
    }
    
    public interface PacketDataInfo {
        String getPlayerName();
        ThreatLevel getThreatLevel();
        int getTotalPacketsLastInterval();
        Map<PacketCategory, Integer> getPacketCounts();
    }
    
    public PacketMonitor(Nantiddos plugin, ConnectionTracker connectionTracker, IPManager ipManager) {
        this.plugin = plugin;
        this.logger = plugin.getLogger();
        this.connectionTracker = connectionTracker;
        this.ipManager = ipManager;
        
        loadConfig();
        registerEvents();
        initializeProtocolLib();
        startAnalysisTask();
    }
    
    public void loadConfig() {
        packetLimitThreshold = plugin.getConfig().getInt("protection.packet-analysis.packet-limit-threshold", 300);
        packetAnalysisInterval = plugin.getConfig().getInt("protection.packet-analysis.analysis-interval-seconds", 10);
        suspiciousPacketThreshold = plugin.getConfig().getInt("protection.packet-analysis.suspicious-packet-threshold", 500);
        autobanThreshold = plugin.getConfig().getInt("protection.packet-analysis.autoban-threshold", 1000);
        autobanEnabled = plugin.getConfig().getBoolean("protection.packet-analysis.autoban-enabled", false);
        intelligentFiltering = plugin.getConfig().getBoolean("protection.packet-analysis.intelligent-filtering", true);
    }
    
    public void enableProtection(boolean enable) {
        this.enabled = enable;
    }
    
    public void shutdown() {
        if (analysisTask != null && !analysisTask.isCancelled()) {
            analysisTask.cancel();
        }
        
        packetDataMap.clear();
        ipStatisticsMap.clear();
    }
    
    private void registerEvents() {
        plugin.getServer().getPluginManager().registerEvents(this, plugin);
    }
    
    private void initializeProtocolLib() {
        Plugin protocolLib = plugin.getServer().getPluginManager().getPlugin("ProtocolLib");
        protocolLibAvailable = protocolLib != null && protocolLib.isEnabled();
        
        if (!protocolLibAvailable) {
            logger.warning("ProtocolLib not found. Advanced packet analysis will be limited.");
            return;
        }
        
        registerPacketListeners();
    }
    
    private void registerPacketListeners() {
        if (!protocolLibAvailable) return;
        
        try {
            Class.forName("com.comphenix.protocol.ProtocolLibrary");
            Class.forName("com.comphenix.protocol.ProtocolManager");
            
            setupProtocolLib();
        } catch (ClassNotFoundException e) {
            logger.severe("Failed to initialize ProtocolLib: " + e.getMessage());
            protocolLibAvailable = false;
        }
    }
    
    private void setupProtocolLib() {
        try {
            com.comphenix.protocol.ProtocolManager protocolManager = com.comphenix.protocol.ProtocolLibrary.getProtocolManager();
            
            protocolManager.addPacketListener(
                new com.comphenix.protocol.events.PacketAdapter(plugin, 
                    com.comphenix.protocol.PacketType.Play.Client.POSITION,
                    com.comphenix.protocol.PacketType.Play.Client.POSITION_LOOK,
                    com.comphenix.protocol.PacketType.Play.Client.LOOK,
                    com.comphenix.protocol.PacketType.Play.Client.FLYING) {
                    
                    @Override
                    public void onPacketReceiving(com.comphenix.protocol.events.PacketEvent event) {
                        if (!enabled || event.isCancelled()) return;
                        
                        Player player = event.getPlayer();
                        if (player == null) return;
                        
                        UUID playerId = player.getUniqueId();
                        PlayerPacketData data = packetDataMap.computeIfAbsent(playerId, k -> new PlayerPacketData(player));
                        
                        data.trackPacket(PacketCategory.MOVEMENT);
                        
                        if (data.shouldThrottlePackets()) {
                            event.setCancelled(true);
                            
                            if (data.getThrottleCount() % 100 == 0) {
                                logger.warning("Throttled excessive movement packets from player: " + player.getName());
                            }
                        }
                    }
                }
            );
            
            protocolManager.addPacketListener(
                new com.comphenix.protocol.events.PacketAdapter(plugin, 
                    com.comphenix.protocol.PacketType.Play.Client.USE_ENTITY,
                    com.comphenix.protocol.PacketType.Play.Client.USE_ITEM,
                    com.comphenix.protocol.PacketType.Play.Client.BLOCK_DIG,
                    com.comphenix.protocol.PacketType.Play.Client.BLOCK_PLACE) {
                    
                    @Override
                    public void onPacketReceiving(com.comphenix.protocol.events.PacketEvent event) {
                        if (!enabled || event.isCancelled()) return;
                        
                        Player player = event.getPlayer();
                        if (player == null) return;
                        
                        UUID playerId = player.getUniqueId();
                        PlayerPacketData data = packetDataMap.computeIfAbsent(playerId, k -> new PlayerPacketData(player));
                        
                        data.trackPacket(PacketCategory.INTERACTION);
                        
                        if (data.shouldThrottlePackets()) {
                            event.setCancelled(true);
                            
                            if (data.getThrottleCount() % 50 == 0) {
                                logger.warning("Throttled excessive interaction packets from player: " + player.getName());
                            }
                        }
                    }
                }
            );
            
            protocolManager.addPacketListener(
                new com.comphenix.protocol.events.PacketAdapter(plugin, 
                    com.comphenix.protocol.PacketType.Play.Client.WINDOW_CLICK,
                    com.comphenix.protocol.PacketType.Play.Client.CLOSE_WINDOW,
                    com.comphenix.protocol.PacketType.Play.Client.CUSTOM_PAYLOAD,
                    com.comphenix.protocol.PacketType.Play.Client.TRANSACTION) {
                    
                    @Override
                    public void onPacketReceiving(com.comphenix.protocol.events.PacketEvent event) {
                        if (!enabled || event.isCancelled()) return;
                        
                        Player player = event.getPlayer();
                        if (player == null) return;
                        
                        UUID playerId = player.getUniqueId();
                        PlayerPacketData data = packetDataMap.computeIfAbsent(playerId, k -> new PlayerPacketData(player));
                        
                        data.trackPacket(PacketCategory.INVENTORY);
                        
                        if (data.shouldThrottlePackets()) {
                            event.setCancelled(true);
                            
                            if (data.getThrottleCount() % 50 == 0) {
                                logger.warning("Throttled excessive inventory packets from player: " + player.getName());
                            }
                        }
                        
                        if (event.getPacketType() == com.comphenix.protocol.PacketType.Play.Client.CUSTOM_PAYLOAD) {
                            com.comphenix.protocol.events.PacketContainer packet = event.getPacket();
                            String channel = packet.getStrings().read(0);
                            
                            if (channel != null && channel.length() > 128) {
                                event.setCancelled(true);
                                data.increaseThrottleCount();
                                data.increaseThreatLevel();
                                
                                logger.warning("Blocked suspicious custom payload packet from player: " + player.getName());
                                
                                if (data.getThreatLevel() == ThreatLevel.HIGH && autobanEnabled) {
                                    applyAutomaticBan(player);
                                }
                            }
                        }
                    }
                }
            );
            
            logger.info("ProtocolLib packet listeners registered successfully");
        } catch (Exception e) {
            logger.severe("Failed to set up ProtocolLib packet listeners: " + e.getMessage());
            protocolLibAvailable = false;
        }
    }
    
    private void startAnalysisTask() {
        analysisTask = Bukkit.getScheduler().runTaskTimerAsynchronously(plugin, () -> {
            if (!enabled) return;
            
            for (Map.Entry<UUID, PlayerPacketData> entry : packetDataMap.entrySet()) {
                PlayerPacketData data = entry.getValue();
                Player player = Bukkit.getPlayer(entry.getKey());
                
                if (player == null || !player.isOnline()) {
                    packetDataMap.remove(entry.getKey());
                    continue;
                }
                
                ThreatLevel threatLevel = analyzeThreatLevel(data);
                data.setThreatLevel(threatLevel);
                
                if (player.getAddress() != null) {
                    String ip = player.getAddress().getAddress().getHostAddress();
                    IpPacketStatistics ipStats = ipStatisticsMap.computeIfAbsent(ip, k -> new IpPacketStatistics());
                    
                    ipStats.updateFromPlayerData(data);
                    
                    if (threatLevel.getLevel() >= ThreatLevel.MEDIUM.getLevel()) {
                        connectionTracker.trackConnection(player.getAddress().getAddress(), 
                            ConnectionTracker.ConnectionType.SUSPICIOUS_PACKETS);
                        
                        if (threatLevel == ThreatLevel.CRITICAL && autobanEnabled) {
                            applyAutomaticBan(player);
                        }
                    }
                }
                
                data.resetPacketCounts();
            }
            
            updateIpStatistics();
            
        }, 20L * packetAnalysisInterval, 20L * packetAnalysisInterval);
    }
    
    private ThreatLevel analyzeThreatLevel(PlayerPacketData data) {
        int totalPackets = data.getTotalPacketsLastInterval();
        
        if (totalPackets > autobanThreshold) {
            return ThreatLevel.CRITICAL;
        } else if (totalPackets > suspiciousPacketThreshold) {
            return ThreatLevel.HIGH;
        } else if (totalPackets > packetLimitThreshold * 1.5) {
            return ThreatLevel.MEDIUM;
        } else if (totalPackets > packetLimitThreshold) {
            return ThreatLevel.LOW;
        } else {
            return ThreatLevel.NONE;
        }
    }
    
    private void updateIpStatistics() {
        for (Map.Entry<String, IpPacketStatistics> entry : ipStatisticsMap.entrySet()) {
            String ip = entry.getKey();
            IpPacketStatistics stats = entry.getValue();
            
            if (stats.getAverageThreatLevel() >= ThreatLevel.HIGH.getLevel()) {
                if (autobanEnabled && !ipManager.isWhitelisted(ip)) {
                    applyAutomaticBan(ip);
                }
            }
            
            stats.resetInterval();
        }
    }
    
    private void applyAutomaticBan(Player player) {
        if (player == null || !player.isOnline() || !autobanEnabled) return;
        
        String ip = player.getAddress().getAddress().getHostAddress();
        applyAutomaticBan(ip);
        
        Bukkit.getScheduler().runTask(plugin, () -> {
            player.kickPlayer("§c§lAutomatic ban: Sending malicious packets");
        });
    }
    
    private void applyAutomaticBan(String ip) {
        if (!autobanEnabled || ip == null || ipManager.isWhitelisted(ip)) return;
        
        Bukkit.getScheduler().runTask(plugin, () -> {
            ipManager.addToBlacklist(ip);
            logger.warning("Automatically blacklisted IP " + ip + " for sending suspicious packets");
            
            for (Player admin : Bukkit.getOnlinePlayers()) {
                if (admin.hasPermission("nantiddos.admin")) {
                    admin.sendMessage("§c[NantiDDoS] §eAutomatically blacklisted §c" + ip + " §efor sending suspicious packets");
                }
            }
        });
    }
    
    @EventHandler(priority = EventPriority.MONITOR)
    public void onPlayerJoin(PlayerJoinEvent event) {
        if (!enabled) return;
        
        Player player = event.getPlayer();
        packetDataMap.put(player.getUniqueId(), new PlayerPacketData(player));
    }
    
    @EventHandler(priority = EventPriority.MONITOR)
    public void onPlayerQuit(PlayerQuitEvent event) {
        packetDataMap.remove(event.getPlayer().getUniqueId());
    }
    
    public Map<UUID, PacketDataInfo> getPacketDataMap() {
        Map<UUID, PacketDataInfo> result = new ConcurrentHashMap<>();
        for (Map.Entry<UUID, PlayerPacketData> entry : packetDataMap.entrySet()) {
            result.put(entry.getKey(), entry.getValue());
        }
        return result;
    }
    
    public Map<String, IpPacketInfo> getIpStatisticsMap() {
        Map<String, IpPacketInfo> result = new ConcurrentHashMap<>();
        for (Map.Entry<String, IpPacketStatistics> entry : ipStatisticsMap.entrySet()) {
            result.put(entry.getKey(), entry.getValue());
        }
        return result;
    }
    
    public boolean isPacketMonitoringFullyAvailable() {
        return protocolLibAvailable;
    }
    
    public int getActivePacketMonitoringSessions() {
        return packetDataMap.size();
    }
    
    public int getSuspiciousPacketSources() {
        int count = 0;
        for (PlayerPacketData data : packetDataMap.values()) {
            if (data.getThreatLevel().getLevel() >= ThreatLevel.MEDIUM.getLevel()) {
                count++;
            }
        }
        return count;
    }
    
    private class PlayerPacketData implements PacketDataInfo {
        private final String playerName;
        private final Map<PacketCategory, Integer> packetCounts = new EnumMap<>(PacketCategory.class);
        private final Map<PacketCategory, Integer> totalCounts = new EnumMap<>(PacketCategory.class);
        private long lastResetTime;
        private int throttleCount;
        private ThreatLevel threatLevel = ThreatLevel.NONE;
        
        public PlayerPacketData(Player player) {
            this.playerName = player.getName();
            lastResetTime = System.currentTimeMillis();
            
            for (PacketCategory category : PacketCategory.values()) {
                packetCounts.put(category, 0);
                totalCounts.put(category, 0);
            }
        }
        
        public void trackPacket(PacketCategory category) {
            packetCounts.put(category, packetCounts.getOrDefault(category, 0) + 1);
            totalCounts.put(category, totalCounts.getOrDefault(category, 0) + 1);
        }
        
        public boolean shouldThrottlePackets() {
            if (!intelligentFiltering) {
                return false;
            }
            
            int movementCount = packetCounts.getOrDefault(PacketCategory.MOVEMENT, 0);
            int interactionCount = packetCounts.getOrDefault(PacketCategory.INTERACTION, 0);
            int inventoryCount = packetCounts.getOrDefault(PacketCategory.INVENTORY, 0);
            
            boolean shouldThrottle = (movementCount > packetLimitThreshold) || 
                                     (interactionCount > packetLimitThreshold / 2) ||
                                     (inventoryCount > packetLimitThreshold / 2);
            
            if (shouldThrottle) {
                throttleCount++;
            }
            
            return shouldThrottle;
        }
        
        public void resetPacketCounts() {
            for (PacketCategory category : PacketCategory.values()) {
                packetCounts.put(category, 0);
            }
            lastResetTime = System.currentTimeMillis();
        }
        
        @Override
        public int getTotalPacketsLastInterval() {
            int total = 0;
            for (Integer count : packetCounts.values()) {
                total += count;
            }
            return total;
        }
        
        @Override
        public Map<PacketCategory, Integer> getPacketCounts() {
            return new EnumMap<>(packetCounts);
        }
        
        public Map<PacketCategory, Integer> getTotalCounts() {
            return new EnumMap<>(totalCounts);
        }
        
        public int getThrottleCount() {
            return throttleCount;
        }
        
        public void increaseThrottleCount() {
            throttleCount++;
        }
        
        @Override
        public String getPlayerName() {
            return playerName;
        }
        
        @Override
        public ThreatLevel getThreatLevel() {
            return threatLevel;
        }
        
        public void setThreatLevel(ThreatLevel level) {
            this.threatLevel = level;
        }
        
        public void increaseThreatLevel() {
            int current = threatLevel.getLevel();
            if (current < ThreatLevel.CRITICAL.getLevel()) {
                for (ThreatLevel level : ThreatLevel.values()) {
                    if (level.getLevel() == current + 1) {
                        threatLevel = level;
                        break;
                    }
                }
            }
        }
    }
    
    public interface IpPacketInfo {
        double getAverageThreatLevel();
    }
    
    private class IpPacketStatistics implements IpPacketInfo {
        private int playerCount;
        private int packetCount;
        private int threatLevelSum;
        private int intervals;
        
        public IpPacketStatistics() {
            this.playerCount = 0;
            this.packetCount = 0;
            this.threatLevelSum = 0;
            this.intervals = 0;
        }
        
        public void updateFromPlayerData(PlayerPacketData data) {
            playerCount++;
            packetCount += data.getTotalPacketsLastInterval();
            threatLevelSum += data.getThreatLevel().getLevel();
            intervals++;
        }
        
        @Override
        public double getAverageThreatLevel() {
            return intervals > 0 ? (double) threatLevelSum / intervals : 0;
        }
        
        public void resetInterval() {
            playerCount = 0;
            packetCount = 0;
            threatLevelSum = 0;
            intervals = 0;
        }
    }
}