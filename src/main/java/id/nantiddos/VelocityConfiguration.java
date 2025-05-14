package id.nantiddos;

import com.google.inject.Inject;
import com.velocitypowered.api.plugin.annotation.DataDirectory;
import org.slf4j.Logger;

import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.file.Path;
import java.util.Properties;
import java.util.UUID;

public class VelocityConfiguration {
    private final Path dataDirectory;
    private final Logger logger;
    private Properties properties;
    private final File configFile;
    
    // Network properties
    private String serverId;
    private String networkId;
    private boolean masterServer;
    private String masterServerId;
    private boolean syncBlacklist;
    private boolean syncWhitelist;
    private boolean syncAttackData;
    private int syncInterval;
    
    // Protection settings
    private int maxConnectionsPerSecond;
    private int botScoreThreshold;
    private int blacklistThreshold;
    private int autoblacklistThreshold;
    private int connectionTimeout;
    private boolean enableProtection;
    private boolean enableAutomaticBlacklisting;
    private boolean intelligentThrottling;
    
    @Inject
    public VelocityConfiguration(Logger logger, @DataDirectory Path dataDirectory) {
        this.logger = logger;
        this.dataDirectory = dataDirectory;
        this.configFile = new File(dataDirectory.toFile(), "config.properties");
        this.properties = new Properties();
        
        loadConfiguration();
    }
    
    public void loadConfiguration() {
        createDefaultConfig();
        
        try (FileReader reader = new FileReader(configFile)) {
            properties.load(reader);
            
            // Load network settings
            serverId = properties.getProperty("network.server-id", generateServerId());
            networkId = properties.getProperty("network.network-id", "default");
            masterServer = Boolean.parseBoolean(properties.getProperty("network.master-server", "false"));
            masterServerId = properties.getProperty("network.master-server-id", "");
            syncBlacklist = Boolean.parseBoolean(properties.getProperty("network.sync-blacklist", "true"));
            syncWhitelist = Boolean.parseBoolean(properties.getProperty("network.sync-whitelist", "true"));
            syncAttackData = Boolean.parseBoolean(properties.getProperty("network.sync-attack-data", "true"));
            syncInterval = Integer.parseInt(properties.getProperty("network.sync-interval-seconds", "30"));
            
            // Load protection settings
            maxConnectionsPerSecond = Integer.parseInt(properties.getProperty("protection.max-connections-per-second", "5"));
            botScoreThreshold = Integer.parseInt(properties.getProperty("protection.bot-score-threshold", "10"));
            blacklistThreshold = Integer.parseInt(properties.getProperty("protection.blacklist-threshold", "25"));
            autoblacklistThreshold = Integer.parseInt(properties.getProperty("protection.autoblacklist-threshold", "30"));
            connectionTimeout = Integer.parseInt(properties.getProperty("protection.connection-timeout", "5000"));
            enableProtection = Boolean.parseBoolean(properties.getProperty("protection.enabled", "true"));
            enableAutomaticBlacklisting = Boolean.parseBoolean(properties.getProperty("protection.automatic-blacklisting", "true"));
            intelligentThrottling = Boolean.parseBoolean(properties.getProperty("protection.intelligent-throttling", "true"));
            
            // Always save to ensure any missing properties are added
            saveConfiguration();
            
        } catch (IOException e) {
            logger.error("Error loading configuration: {}", e.getMessage());
        }
    }
    
    public void createDefaultConfig() {
        if (configFile.exists()) {
            return;
        }
        
        File directory = dataDirectory.toFile();
        if (!directory.exists()) {
            directory.mkdirs();
        }
        
        try (FileWriter writer = new FileWriter(configFile)) {
            Properties defaultProperties = new Properties();
            
            // Network settings
            defaultProperties.setProperty("network.server-id", generateServerId());
            defaultProperties.setProperty("network.network-id", "default");
            defaultProperties.setProperty("network.master-server", "false");
            defaultProperties.setProperty("network.master-server-id", "");
            defaultProperties.setProperty("network.sync-blacklist", "true");
            defaultProperties.setProperty("network.sync-whitelist", "true");
            defaultProperties.setProperty("network.sync-attack-data", "true");
            defaultProperties.setProperty("network.sync-interval-seconds", "30");
            
            // Protection settings
            defaultProperties.setProperty("protection.max-connections-per-second", "5");
            defaultProperties.setProperty("protection.bot-score-threshold", "10");
            defaultProperties.setProperty("protection.blacklist-threshold", "25");
            defaultProperties.setProperty("protection.autoblacklist-threshold", "30");
            defaultProperties.setProperty("protection.connection-timeout", "5000");
            defaultProperties.setProperty("protection.enabled", "true");
            defaultProperties.setProperty("protection.automatic-blacklisting", "true");
            defaultProperties.setProperty("protection.intelligent-throttling", "true");
            
            // Messages
            defaultProperties.setProperty("messages.kick-message", "Connection throttled! Please wait before reconnecting.");
            defaultProperties.setProperty("messages.blacklisted-message", "Your IP address is blacklisted from this server.");
            defaultProperties.setProperty("messages.packet-flood-message", "You have been kicked for sending too many packets to the server.");
            
            defaultProperties.store(writer, "NantiDDoS Velocity Configuration");
            
            this.properties = defaultProperties;
            
        } catch (IOException e) {
            logger.error("Error creating default configuration: {}", e.getMessage());
        }
    }
    
    public void saveConfiguration() {
        try (FileWriter writer = new FileWriter(configFile)) {
            // Update properties with current values
            properties.setProperty("network.server-id", serverId);
            properties.setProperty("network.network-id", networkId);
            properties.setProperty("network.master-server", String.valueOf(masterServer));
            properties.setProperty("network.master-server-id", masterServerId);
            properties.setProperty("network.sync-blacklist", String.valueOf(syncBlacklist));
            properties.setProperty("network.sync-whitelist", String.valueOf(syncWhitelist));
            properties.setProperty("network.sync-attack-data", String.valueOf(syncAttackData));
            properties.setProperty("network.sync-interval-seconds", String.valueOf(syncInterval));
            
            properties.setProperty("protection.max-connections-per-second", String.valueOf(maxConnectionsPerSecond));
            properties.setProperty("protection.bot-score-threshold", String.valueOf(botScoreThreshold));
            properties.setProperty("protection.blacklist-threshold", String.valueOf(blacklistThreshold));
            properties.setProperty("protection.autoblacklist-threshold", String.valueOf(autoblacklistThreshold));
            properties.setProperty("protection.connection-timeout", String.valueOf(connectionTimeout));
            properties.setProperty("protection.enabled", String.valueOf(enableProtection));
            properties.setProperty("protection.automatic-blacklisting", String.valueOf(enableAutomaticBlacklisting));
            properties.setProperty("protection.intelligent-throttling", String.valueOf(intelligentThrottling));
            
            properties.store(writer, "NantiDDoS Velocity Configuration");
            
        } catch (IOException e) {
            logger.error("Error saving configuration: {}", e.getMessage());
        }
    }
    
    private String generateServerId() {
        return UUID.randomUUID().toString().substring(0, 8);
    }
    
    // Getters and setters
    public String getServerId() {
        return serverId;
    }
    
    public void setServerId(String serverId) {
        this.serverId = serverId;
        saveConfiguration();
    }
    
    public String getNetworkId() {
        return networkId;
    }
    
    public void setNetworkId(String networkId) {
        this.networkId = networkId;
        saveConfiguration();
    }
    
    public boolean isMasterServer() {
        return masterServer;
    }
    
    public void setMasterServer(boolean masterServer) {
        this.masterServer = masterServer;
        saveConfiguration();
    }
    
    public String getMasterServerId() {
        return masterServerId;
    }
    
    public void setMasterServerId(String masterServerId) {
        this.masterServerId = masterServerId;
        saveConfiguration();
    }
    
    public boolean isSyncBlacklist() {
        return syncBlacklist;
    }
    
    public boolean isSyncWhitelist() {
        return syncWhitelist;
    }
    
    public boolean isSyncAttackData() {
        return syncAttackData;
    }
    
    public int getSyncInterval() {
        return syncInterval;
    }
    
    public int getMaxConnectionsPerSecond() {
        return maxConnectionsPerSecond;
    }
    
    public int getBotScoreThreshold() {
        return botScoreThreshold;
    }
    
    public int getBlacklistThreshold() {
        return blacklistThreshold;
    }
    
    public int getAutoblacklistThreshold() {
        return autoblacklistThreshold;
    }
    
    public int getConnectionTimeout() {
        return connectionTimeout;
    }
    
    public boolean isEnableProtection() {
        return enableProtection;
    }
    
    public void setEnableProtection(boolean enableProtection) {
        this.enableProtection = enableProtection;
        saveConfiguration();
    }
    
    public boolean isEnableAutomaticBlacklisting() {
        return enableAutomaticBlacklisting;
    }
    
    public boolean isIntelligentThrottling() {
        return intelligentThrottling;
    }
}