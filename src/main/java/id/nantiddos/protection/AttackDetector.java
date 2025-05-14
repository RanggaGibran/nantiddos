package id.nantiddos.protection;

import id.nantiddos.Nantiddos;

import java.net.InetAddress;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.EnumMap;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Queue;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import java.util.logging.Logger;

import org.bukkit.Bukkit;
import org.bukkit.configuration.ConfigurationSection;
import org.bukkit.configuration.file.FileConfiguration;
import org.bukkit.entity.Player;
import org.bukkit.scheduler.BukkitTask;

public class AttackDetector {
    private final Nantiddos plugin;
    private final Logger logger;
    private final ConnectionTracker connectionTracker;
    private final IPManager ipManager;
    private final PacketMonitor packetMonitor;
    
    private BukkitTask analysisTask;
    private boolean enabled = true;
    
    private final Map<AttackType, AttackSignature> attackSignatures = new EnumMap<>(AttackType.class);
    private final Map<String, AttackData> attackDataMap = new ConcurrentHashMap<>();
    private final List<AttackRecord> recentAttacks = Collections.synchronizedList(new ArrayList<>());
    
    private int analysisIntervalSeconds;
    private int dataRetentionMinutes;
    private int autobanThreshold;
    private int autoblacklistThreshold;
    private int attackHistorySize;
    private boolean autobanEnabled;
    private boolean autoblacklistEnabled;
    private boolean adaptiveThresholds;
    
    public enum AttackType {
        CONNECTION_FLOOD("Connection Flooding", "Excessive connection attempts in short time period", 10),
        LOGIN_FLOOD("Login Flooding", "Excessive login attempts in short time period", 15),
        PING_FLOOD("Ping Flooding", "Excessive server list ping requests", 8),
        PACKET_FLOOD("Packet Flooding", "Excessive packets sent to the server", 20),
        BOT_NETWORK("Bot Network", "Multiple IPs with similar behavior patterns", 25),
        DISTRIBUTED_ATTACK("Distributed Attack", "Coordinated attack from multiple sources", 30);
        
        private final String name;
        private final String description;
        private final int baseRiskScore;
        
        AttackType(String name, String description, int baseRiskScore) {
            this.name = name;
            this.description = description;
            this.baseRiskScore = baseRiskScore;
        }
        
        public String getName() {
            return name;
        }
        
        public String getDescription() {
            return description;
        }
        
        public int getBaseRiskScore() {
            return baseRiskScore;
        }
    }
    
    public enum AlertLevel {
        NORMAL(0, "§a"),
        LOW(1, "§e"),
        MEDIUM(2, "§6"),
        HIGH(3, "§c"),
        CRITICAL(4, "§4");
        
        private final int level;
        private final String color;
        
        AlertLevel(int level, String color) {
            this.level = level;
            this.color = color;
        }
        
        public int getLevel() {
            return level;
        }
        
        public String getColor() {
            return color;
        }
        
        public static AlertLevel fromRiskScore(int riskScore) {
            if (riskScore >= 80) return CRITICAL;
            if (riskScore >= 60) return HIGH;
            if (riskScore >= 40) return MEDIUM;
            if (riskScore >= 20) return LOW;
            return NORMAL;
        }
    }
    
    public AttackDetector(Nantiddos plugin, ConnectionTracker connectionTracker, IPManager ipManager, PacketMonitor packetMonitor) {
        this.plugin = plugin;
        this.logger = plugin.getLogger();
        this.connectionTracker = connectionTracker;
        this.ipManager = ipManager;
        this.packetMonitor = packetMonitor;
        
        loadConfig();
        initializeAttackSignatures();
        startAnalysisTask();
        
        logger.info("Attack pattern recognition system initialized");
    }
    
    public void loadConfig() {
        FileConfiguration config = plugin.getConfig();
        
        analysisIntervalSeconds = config.getInt("protection.attack-detection.analysis-interval-seconds", 30);
        dataRetentionMinutes = config.getInt("protection.attack-detection.data-retention-minutes", 60);
        autobanThreshold = config.getInt("protection.attack-detection.autoban-threshold", 75);
        autoblacklistThreshold = config.getInt("protection.attack-detection.autoblacklist-threshold", 85);
        attackHistorySize = config.getInt("protection.attack-detection.attack-history-size", 50);
        autobanEnabled = config.getBoolean("protection.attack-detection.autoban-enabled", false);
        autoblacklistEnabled = config.getBoolean("protection.attack-detection.autoblacklist-enabled", false);
        adaptiveThresholds = config.getBoolean("protection.attack-detection.adaptive-thresholds", true);
        
        ConfigurationSection signatureSection = config.getConfigurationSection("protection.attack-detection.signatures");
        if (signatureSection != null) {
            for (AttackType type : AttackType.values()) {
                ConfigurationSection typeSection = signatureSection.getConfigurationSection(type.name());
                if (typeSection != null) {
                    int threshold = typeSection.getInt("threshold", type.getBaseRiskScore() * 5);
                    int decayRate = typeSection.getInt("decay-rate", 1);
                    
                    if (attackSignatures.containsKey(type)) {
                        attackSignatures.get(type).setThreshold(threshold);
                        attackSignatures.get(type).setDecayRate(decayRate);
                    }
                }
            }
        }
    }
    
    public void shutdown() {
        if (analysisTask != null && !analysisTask.isCancelled()) {
            analysisTask.cancel();
        }
        
        attackDataMap.clear();
    }
    
    public void enableProtection(boolean enable) {
        this.enabled = enable;
    }
    
    private void initializeAttackSignatures() {
        for (AttackType type : AttackType.values()) {
            attackSignatures.put(type, new AttackSignature(type));
        }
    }
    
    private void startAnalysisTask() {
        analysisTask = Bukkit.getScheduler().runTaskTimerAsynchronously(plugin, () -> {
            if (!enabled) return;
            
            analyzeConnectionPatterns();
            analyzePacketPatterns();
            analyzeDistributedAttacks();
            cleanupOldData();
            
        }, 20L * analysisIntervalSeconds, 20L * analysisIntervalSeconds);
    }
    
    private void analyzeConnectionPatterns() {
        Map<String, ConnectionTracker.ConnectionData> connections = connectionTracker.getConnectionMap();
        Map<String, Integer> botScores = connectionTracker.getBotScores();
        
        for (Map.Entry<String, ConnectionTracker.ConnectionData> entry : connections.entrySet()) {
            String ip = entry.getKey();
            ConnectionTracker.ConnectionData data = entry.getValue();
            
            if (ipManager.isWhitelisted(ip)) continue;
            
            AttackData attackData = attackDataMap.computeIfAbsent(ip, k -> new AttackData(ip));
            
            int connectionsPerSecond = data.getConnectionsPerSecond();
            int pingCount = data.getPingCount();
            int loginCount = data.getLoginCount();
            int botScore = botScores.getOrDefault(ip, 0);
            
            if (connectionsPerSecond > 10) {
                int severity = calculateConnectionFloodSeverity(connectionsPerSecond);
                attackData.addSignatureMatch(AttackType.CONNECTION_FLOOD, severity);
            }
            
            if (loginCount > 5 && (System.currentTimeMillis() - data.getLastValidLogin()) < 60000) {
                int severity = calculateLoginFloodSeverity(loginCount);
                attackData.addSignatureMatch(AttackType.LOGIN_FLOOD, severity);
            }
            
            if (pingCount > 30) {
                int severity = calculatePingFloodSeverity(pingCount);
                attackData.addSignatureMatch(AttackType.PING_FLOOD, severity);
            }
            
            if (botScore > 15) {
                attackData.increaseThreatScore(botScore / 5);
            }
        }
    }
    
    private void analyzePacketPatterns() {
        if (packetMonitor == null || !packetMonitor.isPacketMonitoringFullyAvailable()) return;
        
        Map<UUID, PacketMonitor.PlayerPacketData> packetData = packetMonitor.getPacketDataMap();
        Map<String, PacketMonitor.IpPacketStatistics> ipStats = packetMonitor.getIpStatisticsMap();
        
        for (Map.Entry<String, PacketMonitor.IpPacketStatistics> entry : ipStats.entrySet()) {
            String ip = entry.getKey();
            
            if (ipManager.isWhitelisted(ip)) continue;
            
            AttackData attackData = attackDataMap.computeIfAbsent(ip, k -> new AttackData(ip));
            double avgThreatLevel = entry.getValue().getAverageThreatLevel();
            
            if (avgThreatLevel > 2.0) {
                int severity = (int)(avgThreatLevel * 15);
                attackData.addSignatureMatch(AttackType.PACKET_FLOOD, severity);
            }
        }
        
        for (Player player : Bukkit.getOnlinePlayers()) {
            if (player.getAddress() == null) continue;
            
            String ip = player.getAddress().getAddress().getHostAddress();
            UUID playerId = player.getUniqueId();
            
            if (ipManager.isWhitelisted(ip) || !packetData.containsKey(playerId)) continue;
            
            PacketMonitor.PlayerPacketData playerData = packetData.get(playerId);
            AttackData attackData = attackDataMap.computeIfAbsent(ip, k -> new AttackData(ip));
            
            if (playerData.getThreatLevel().getLevel() >= 3) {
                attackData.addSignatureMatch(AttackType.PACKET_FLOOD, 30);
            }
        }
    }
    
    private void analyzeDistributedAttacks() {
        Map<String, Integer> ipClassCounts = new HashMap<>();
        Map<Integer, List<String>> classToIps = new HashMap<>();
        
        for (Map.Entry<String, AttackData> entry : attackDataMap.entrySet()) {
            String ip = entry.getKey();
            AttackData data = entry.getValue();
            
            if (data.getCurrentRiskScore() < 20) continue;
            
            String ipClass = getIpClass(ip);
            ipClassCounts.put(ipClass, ipClassCounts.getOrDefault(ipClass, 0) + 1);
            
            List<String> ips = classToIps.getOrDefault(getNetworkHash(ip), new ArrayList<>());
            ips.add(ip);
            classToIps.put(getNetworkHash(ip), ips);
        }
        
        for (Map.Entry<Integer, List<String>> entry : classToIps.entrySet()) {
            List<String> ips = entry.getValue();
            
            if (ips.size() >= 3) {
                boolean similarPattern = hasSimilarAttackPattern(ips);
                
                if (similarPattern) {
                    for (String ip : ips) {
                        AttackData attackData = attackDataMap.get(ip);
                        if (attackData != null) {
                            attackData.addSignatureMatch(AttackType.BOT_NETWORK, 25);
                            
                            if (ips.size() >= 5) {
                                attackData.addSignatureMatch(AttackType.DISTRIBUTED_ATTACK, 30);
                            }
                        }
                    }
                    
                    registerAttackEvent(AttackType.DISTRIBUTED_ATTACK, ips);
                }
            }
        }
    }
    
    private void cleanupOldData() {
        long expirationTime = System.currentTimeMillis() - TimeUnit.MINUTES.toMillis(dataRetentionMinutes);
        
        attackDataMap.entrySet().removeIf(entry -> entry.getValue().getLastUpdated() < expirationTime);
        
        while (recentAttacks.size() > attackHistorySize) {
            recentAttacks.remove(0);
        }
    }
    
    private boolean hasSimilarAttackPattern(List<String> ips) {
        if (ips.size() < 2) return false;
        
        Map<AttackType, Integer> signatureCounts = new EnumMap<>(AttackType.class);
        
        for (String ip : ips) {
            AttackData data = attackDataMap.get(ip);
            if (data == null) continue;
            
            for (AttackType type : data.getDetectedAttackTypes()) {
                signatureCounts.put(type, signatureCounts.getOrDefault(type, 0) + 1);
            }
        }
        
        for (Map.Entry<AttackType, Integer> entry : signatureCounts.entrySet()) {
            if (entry.getValue() >= ips.size() * 0.6) {
                return true;
            }
        }
        
        return false;
    }
    
    private int calculateConnectionFloodSeverity(int connectionsPerSecond) {
        if (connectionsPerSecond > 30) return 60;
        if (connectionsPerSecond > 20) return 40;
        if (connectionsPerSecond > 10) return 20;
        return 10;
    }
    
    private int calculateLoginFloodSeverity(int loginCount) {
        if (loginCount > 20) return 50;
        if (loginCount > 10) return 30;
        if (loginCount > 5) return 20;
        return 10;
    }
    
    private int calculatePingFloodSeverity(int pingCount) {
        if (pingCount > 100) return 40;
        if (pingCount > 50) return 25;
        if (pingCount > 30) return 15;
        return 5;
    }
    
    public void checkAndApplyMitigations() {
        for (Map.Entry<String, AttackData> entry : attackDataMap.entrySet()) {
            String ip = entry.getKey();
            AttackData data = entry.getValue();
            
            if (data.getAlertLevel() == AlertLevel.CRITICAL) {
                if (autoblacklistEnabled && data.getCurrentRiskScore() >= autoblacklistThreshold) {
                    applyAutomaticBlacklist(ip, data);
                } else if (autobanEnabled && data.getCurrentRiskScore() >= autobanThreshold) {
                    applyAutomaticBan(ip, data);
                }
            }
        }
    }
    
    private void applyAutomaticBan(String ip, AttackData data) {
        if (!autobanEnabled || ip == null || ipManager.isWhitelisted(ip)) return;
        
        for (Player player : Bukkit.getOnlinePlayers()) {
            if (player.getAddress() != null && ip.equals(player.getAddress().getAddress().getHostAddress())) {
                Bukkit.getScheduler().runTask(plugin, () -> {
                    player.kickPlayer("§c§lAutomatic ban: Detected attack pattern: " + 
                                     data.getPrimaryAttackType().getName());
                });
            }
        }
        
        logger.warning("Auto-kicked player with IP " + ip + " for detected attack pattern: " + 
                     data.getPrimaryAttackType().getName());
    }
    
    private void applyAutomaticBlacklist(String ip, AttackData data) {
        if (!autoblacklistEnabled || ip == null || ipManager.isWhitelisted(ip)) return;
        
        Bukkit.getScheduler().runTask(plugin, () -> {
            if (ipManager.addToBlacklist(ip)) {
                logger.warning("Automatically blacklisted IP " + ip + " for attack pattern: " + 
                             data.getPrimaryAttackType().getName());
                
                for (Player admin : Bukkit.getOnlinePlayers()) {
                    if (admin.hasPermission("nantiddos.admin")) {
                        admin.sendMessage("§c[NantiDDoS] §eAutomatically blacklisted §c" + ip + 
                                       " §efor attack pattern: §c" + data.getPrimaryAttackType().getName());
                    }
                }
                
                for (Player player : Bukkit.getOnlinePlayers()) {
                    if (player.getAddress() != null && ip.equals(player.getAddress().getAddress().getHostAddress())) {
                        player.kickPlayer("§c§lYour IP has been blacklisted for detected attack pattern: " + 
                                        data.getPrimaryAttackType().getName());
                    }
                }
            }
        });
    }
    
    public void registerAttackEvent(AttackType type, List<String> ips) {
        AttackRecord record = new AttackRecord(type, ips);
        recentAttacks.add(record);
        
        logger.warning("Attack detected: " + type.getName() + " from " + ips.size() + " IPs");
        
        for (Player admin : Bukkit.getOnlinePlayers()) {
            if (admin.hasPermission("nantiddos.admin")) {
                admin.sendMessage("§c[NantiDDoS] §eAttack detected: §c" + type.getName() + 
                               " §efrom §c" + ips.size() + " §eIPs");
            }
        }
    }
    
    private String getIpClass(String ip) {
        String[] octets = ip.split("\\.");
        if (octets.length != 4) return "";
        return octets[0] + "." + octets[1];
    }
    
    private int getNetworkHash(String ip) {
        String[] octets = ip.split("\\.");
        if (octets.length != 4) return 0;
        
        try {
            return Integer.parseInt(octets[0]) * 256 + Integer.parseInt(octets[1]);
        } catch (NumberFormatException e) {
            return 0;
        }
    }
    
    public Map<String, AttackData> getAttackDataMap() {
        return attackDataMap;
    }
    
    public List<AttackRecord> getRecentAttacks() {
        return new ArrayList<>(recentAttacks);
    }
    
    public int getCurrentThreatLevel() {
        int highestScore = 0;
        
        for (AttackData data : attackDataMap.values()) {
            if (data.getCurrentRiskScore() > highestScore) {
                highestScore = data.getCurrentRiskScore();
            }
        }
        
        return highestScore;
    }
    
    public AlertLevel getSystemAlertLevel() {
        return AlertLevel.fromRiskScore(getCurrentThreatLevel());
    }
    
    public int getActiveAttackSourcesCount() {
        int count = 0;
        
        for (AttackData data : attackDataMap.values()) {
            if (data.getAlertLevel().getLevel() >= AlertLevel.MEDIUM.getLevel()) {
                count++;
            }
        }
        
        return count;
    }
    
    public class AttackSignature {
        private final AttackType type;
        private int threshold;
        private int decayRate;
        
        public AttackSignature(AttackType type) {
            this.type = type;
            this.threshold = type.getBaseRiskScore() * 5;
            this.decayRate = 1;
        }
        
        public AttackType getType() {
            return type;
        }
        
        public int getThreshold() {
            return threshold;
        }
        
        public void setThreshold(int threshold) {
            this.threshold = threshold;
        }
        
        public int getDecayRate() {
            return decayRate;
        }
        
        public void setDecayRate(int decayRate) {
            this.decayRate = decayRate;
        }
    }
    
    public class AttackData {
        private final String ip;
        private final Map<AttackType, Integer> signatureMatches = new EnumMap<>(AttackType.class);
        private final Queue<AttackRecord> attackHistory = new LinkedList<>();
        private int currentRiskScore = 0;
        private long lastUpdated;
        
        public AttackData(String ip) {
            this.ip = ip;
            this.lastUpdated = System.currentTimeMillis();
        }
        
        public void addSignatureMatch(AttackType type, int severity) {
            int currentSeverity = signatureMatches.getOrDefault(type, 0);
            signatureMatches.put(type, Math.min(100, currentSeverity + severity));
            
            increaseThreatScore(severity / 4);
            lastUpdated = System.currentTimeMillis();
        }
        
        public void increaseThreatScore(int amount) {
            currentRiskScore = Math.min(100, currentRiskScore + amount);
            lastUpdated = System.currentTimeMillis();
        }
        
        public void decreaseThreatScore(int amount) {
            currentRiskScore = Math.max(0, currentRiskScore - amount);
        }
        
        public String getIp() {
            return ip;
        }
        
        public int getCurrentRiskScore() {
            return currentRiskScore;
        }
        
        public Map<AttackType, Integer> getSignatureMatches() {
            return signatureMatches;
        }
        
        public List<AttackType> getDetectedAttackTypes() {
            List<AttackType> types = new ArrayList<>();
            
            for (Map.Entry<AttackType, Integer> entry : signatureMatches.entrySet()) {
                if (entry.getValue() > attackSignatures.get(entry.getKey()).getThreshold() / 2) {
                    types.add(entry.getKey());
                }
            }
            
            return types;
        }
        
        public AttackType getPrimaryAttackType() {
            AttackType primary = AttackType.CONNECTION_FLOOD;
            int highestSeverity = 0;
            
            for (Map.Entry<AttackType, Integer> entry : signatureMatches.entrySet()) {
                if (entry.getValue() > highestSeverity) {
                    highestSeverity = entry.getValue();
                    primary = entry.getKey();
                }
            }
            
            return primary;
        }
        
        public long getLastUpdated() {
            return lastUpdated;
        }
        
        public AlertLevel getAlertLevel() {
            return AlertLevel.fromRiskScore(currentRiskScore);
        }
        
        public void addAttackRecord(AttackRecord record) {
            attackHistory.add(record);
            
            while (attackHistory.size() > 10) {
                attackHistory.poll();
            }
        }
        
        public Queue<AttackRecord> getAttackHistory() {
            return attackHistory;
        }
    }
    
    public class AttackRecord {
        private final AttackType type;
        private final List<String> sourceIps;
        private final long timestamp;
        
        public AttackRecord(AttackType type, List<String> sourceIps) {
            this.type = type;
            this.sourceIps = new ArrayList<>(sourceIps);
            this.timestamp = System.currentTimeMillis();
        }
        
        public AttackType getType() {
            return type;
        }
        
        public List<String> getSourceIps() {
            return sourceIps;
        }
        
        public long getTimestamp() {
            return timestamp;
        }
    }
}