package id.nantiddos.protection;

import id.nantiddos.Nantiddos;

import java.net.InetAddress;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import java.util.logging.Logger;

import org.bukkit.Bukkit;
import org.bukkit.entity.Player;
import org.bukkit.scheduler.BukkitTask;

public class ConnectionTracker {
    private final Nantiddos plugin;
    private final Logger logger;
    
    private final ConcurrentHashMap<String, ConnectionData> connectionMap = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, Integer> botScores = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<UUID, String> playerIpCache = new ConcurrentHashMap<>();
    
    private BukkitTask cleanupTask;
    private boolean enabled = true;
    
    private int connectionThreshold;
    private int botScoreThreshold;
    private int cleanupIntervalMinutes;
    private int dataExpirationMinutes;
    private boolean intelligentThrottling;

    public ConnectionTracker(Nantiddos plugin) {
        this.plugin = plugin;
        this.logger = plugin.getLogger();
        loadConfig();
        startCleanupTask();
    }
    
    public void loadConfig() {
        connectionThreshold = plugin.getConfig().getInt("protection.advanced.connection-threshold", 5);
        botScoreThreshold = plugin.getConfig().getInt("protection.advanced.bot-score-threshold", 10);
        cleanupIntervalMinutes = plugin.getConfig().getInt("protection.advanced.cleanup-interval-minutes", 15);
        dataExpirationMinutes = plugin.getConfig().getInt("protection.advanced.data-expiration-minutes", 60);
        intelligentThrottling = plugin.getConfig().getBoolean("protection.advanced.intelligent-throttling", true);
    }
    
    public void shutdown() {
        if (cleanupTask != null && !cleanupTask.isCancelled()) {
            cleanupTask.cancel();
        }
    }
    
    public void enableProtection(boolean enable) {
        this.enabled = enable;
    }
    
    public void trackConnection(InetAddress address, ConnectionType type) {
        if (!enabled) return;
        
        String ip = address.getHostAddress();
        ConnectionData data = connectionMap.computeIfAbsent(ip, k -> new ConnectionData());
        
        switch (type) {
            case SERVER_PING:
                data.incrementPings();
                break;
            case LOGIN_ATTEMPT:
                data.incrementLogins();
                break;
            case CHAT_MESSAGE:
                data.incrementChatMessages();
                break;
            case COMMAND:
                data.incrementCommands();
                break;
        }
        
        analyzeConnectionPattern(ip, data);
    }
    
    public void registerPlayerConnection(UUID playerId, InetAddress address) {
        String ip = address.getHostAddress();
        playerIpCache.put(playerId, ip);
        
        ConnectionData data = connectionMap.get(ip);
        if (data != null) {
            data.setLastValidLogin(System.currentTimeMillis());
            data.associatePlayer(playerId);
            
            botScores.put(ip, Math.max(0, botScores.getOrDefault(ip, 0) - 2));
        }
    }
    
    public boolean shouldThrottleConnection(InetAddress address) {
        if (!enabled) return false;
        
        String ip = address.getHostAddress();
        ConnectionData data = connectionMap.get(ip);
        
        if (data == null) return false;
        
        if (data.isWhitelisted()) return false;
        
        int botScore = botScores.getOrDefault(ip, 0);
        if (botScore >= botScoreThreshold) {
            return true;
        }
        
        long currentTime = System.currentTimeMillis();
        long timeDiff = currentTime - data.getLastConnectionTime();
        
        if (timeDiff < 1000) {
            if (data.getConnectionsPerSecond() > connectionThreshold) {
                if (intelligentThrottling) {
                    int serverLoad = getApproximateServerLoad();
                    if (serverLoad > 70) {
                        return data.getConnectionsPerSecond() > (connectionThreshold / 2);
                    }
                }
                
                return true;
            }
        }
        
        return false;
    }
    
    public void registerSuccessfulLogin(String ip) {
        ConnectionData data = connectionMap.get(ip);
        if (data != null) {
            data.setLastValidLogin(System.currentTimeMillis());
            botScores.put(ip, 0);
        }
    }
    
    public void clearData() {
        connectionMap.clear();
        botScores.clear();
    }
    
    public void clearData(String ip) {
        connectionMap.remove(ip);
        botScores.remove(ip);
    }
    
    public Map<String, ConnectionData> getConnectionMap() {
        return connectionMap;
    }
    
    public Map<String, Integer> getBotScores() {
        return botScores;
    }
    
    public int getConnectionsCount() {
        return connectionMap.size();
    }
    
    public int getSuspiciousConnectionsCount() {
        return (int) botScores.entrySet().stream()
                .filter(e -> e.getValue() >= botScoreThreshold)
                .count();
    }
    
    private void analyzeConnectionPattern(String ip, ConnectionData data) {
        long currentTime = System.currentTimeMillis();
        
        int currentScore = botScores.getOrDefault(ip, 0);
        
        if (data.getConnectionsPerSecond() > connectionThreshold * 2) {
            currentScore += 3;
        } else if (data.getConnectionsPerSecond() > connectionThreshold) {
            currentScore += 1;
        }
        
        if (data.getPingCount() > 20 && data.getLoginCount() == 0) {
            currentScore += 2;
        }
        
        if (currentTime - data.getLastValidLogin() > TimeUnit.HOURS.toMillis(1) && 
                data.getLoginCount() > 10) {
            currentScore += 2;
        }
        
        botScores.put(ip, Math.min(currentScore, 100));
    }
    
    private void startCleanupTask() {
        cleanupTask = Bukkit.getScheduler().runTaskTimerAsynchronously(plugin, () -> {
            long currentTime = System.currentTimeMillis();
            long expirationTime = currentTime - TimeUnit.MINUTES.toMillis(dataExpirationMinutes);
            
            connectionMap.entrySet().removeIf(entry -> 
                entry.getValue().getLastConnectionTime() < expirationTime);
                
            botScores.entrySet().removeIf(entry -> 
                !connectionMap.containsKey(entry.getKey()) || entry.getValue() <= 0);
                
        }, 20 * 60 * cleanupIntervalMinutes, 20 * 60 * cleanupIntervalMinutes);
    }
    
    private int getApproximateServerLoad() {
        Runtime runtime = Runtime.getRuntime();
        long maxMemory = runtime.maxMemory() / 1024 / 1024;
        long totalMemory = runtime.totalMemory() / 1024 / 1024;
        long freeMemory = runtime.freeMemory() / 1024 / 1024;
        long usedMemory = totalMemory - freeMemory;
        
        double memoryUsagePercent = ((double) usedMemory / maxMemory) * 100;
        int playerCount = Bukkit.getOnlinePlayers().size();
        int maxPlayers = Bukkit.getMaxPlayers();
        double playerLoadPercent = ((double) playerCount / maxPlayers) * 100;
        
        return (int) ((memoryUsagePercent * 0.7) + (playerLoadPercent * 0.3));
    }
    
    public enum ConnectionType {
        SERVER_PING,
        LOGIN_ATTEMPT,
        CHAT_MESSAGE,
        COMMAND
    }
    
    public static class ConnectionData {
        private long firstConnectionTime;
        private long lastConnectionTime;
        private long lastValidLogin;
        private int pingCount;
        private int loginCount;
        private int chatMessageCount;
        private int commandCount;
        private int connectionsLastSecond;
        private UUID lastPlayerId;
        private boolean whitelisted;
        
        public ConnectionData() {
            firstConnectionTime = System.currentTimeMillis();
            lastConnectionTime = firstConnectionTime;
        }
        
        public void incrementPings() {
            pingCount++;
            updateConnectionTime();
        }
        
        public void incrementLogins() {
            loginCount++;
            updateConnectionTime();
        }
        
        public void incrementChatMessages() {
            chatMessageCount++;
        }
        
        public void incrementCommands() {
            commandCount++;
        }
        
        public void associatePlayer(UUID playerId) {
            this.lastPlayerId = playerId;
        }
        
        private void updateConnectionTime() {
            long currentTime = System.currentTimeMillis();
            if (currentTime - lastConnectionTime < 1000) {
                connectionsLastSecond++;
            } else {
                connectionsLastSecond = 1;
            }
            lastConnectionTime = currentTime;
        }
        
        public long getFirstConnectionTime() {
            return firstConnectionTime;
        }
        
        public long getLastConnectionTime() {
            return lastConnectionTime;
        }
        
        public int getPingCount() {
            return pingCount;
        }
        
        public int getLoginCount() {
            return loginCount;
        }
        
        public int getChatMessageCount() {
            return chatMessageCount;
        }
        
        public int getCommandCount() {
            return commandCount;
        }
        
        public int getConnectionsPerSecond() {
            return connectionsLastSecond;
        }
        
        public UUID getLastPlayerId() {
            return lastPlayerId;
        }
        
        public void setLastValidLogin(long time) {
            this.lastValidLogin = time;
        }
        
        public long getLastValidLogin() {
            return lastValidLogin;
        }
        
        public boolean isWhitelisted() {
            return whitelisted;
        }
        
        public void setWhitelisted(boolean whitelisted) {
            this.whitelisted = whitelisted;
        }
    }
}