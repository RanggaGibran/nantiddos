package id.nantiddos.protection;

import id.nantiddos.Nantiddos;

import java.io.File;
import java.io.IOException;
import java.net.InetAddress;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.logging.Logger;
import java.util.regex.Pattern;

import org.bukkit.Bukkit;
import org.bukkit.configuration.file.FileConfiguration;
import org.bukkit.configuration.file.YamlConfiguration;
import org.bukkit.scheduler.BukkitTask;

public class IPManager {
    private final Nantiddos plugin;
    private final Logger logger;
    private final File whitelistFile;
    private final File blacklistFile;
    
    private Set<String> whitelistedIps = new HashSet<>();
    private Set<String> blacklistedIps = new HashSet<>();
    private List<CIDREntry> whitelistedNetworks = new ArrayList<>();
    private List<CIDREntry> blacklistedNetworks = new ArrayList<>();
    
    private BukkitTask autoSaveTask;
    private boolean autoSaveEnabled;
    private int autoSaveInterval;
    private boolean blockByDefault;
    
    private static final Pattern IP_PATTERN = Pattern.compile(
        "^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$");
    
    private static final Pattern CIDR_PATTERN = Pattern.compile(
        "^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])(\\/([0-9]|[1-2][0-9]|3[0-2]))$");

    public IPManager(Nantiddos plugin) {
        this.plugin = plugin;
        this.logger = plugin.getLogger();
        
        File dataFolder = plugin.getDataFolder();
        this.whitelistFile = new File(dataFolder, "whitelist.yml");
        this.blacklistFile = new File(dataFolder, "blacklist.yml");
        
        loadConfig();
        loadLists();
        startAutoSave();
    }

    public void loadConfig() {
        FileConfiguration config = plugin.getConfig();
        autoSaveEnabled = config.getBoolean("protection.ip-management.auto-save", true);
        autoSaveInterval = config.getInt("protection.ip-management.auto-save-interval-minutes", 10);
        blockByDefault = config.getBoolean("protection.ip-management.block-by-default", false);
    }
    
    public void shutdown() {
        if (autoSaveTask != null && !autoSaveTask.isCancelled()) {
            autoSaveTask.cancel();
        }
        saveLists();
    }
    
    private void loadLists() {
        loadWhitelist();
        loadBlacklist();
    }
    
    private void loadWhitelist() {
        whitelistedIps.clear();
        whitelistedNetworks.clear();
        
        if (!whitelistFile.exists()) {
            try {
                whitelistFile.createNewFile();
                FileConfiguration whitelistConfig = YamlConfiguration.loadConfiguration(whitelistFile);
                whitelistConfig.set("whitelist", new ArrayList<String>());
                whitelistConfig.set("networks", new ArrayList<String>());
                whitelistConfig.save(whitelistFile);
            } catch (IOException e) {
                logger.severe("Failed to create whitelist.yml: " + e.getMessage());
                return;
            }
        }
        
        FileConfiguration whitelistConfig = YamlConfiguration.loadConfiguration(whitelistFile);
        List<String> ips = whitelistConfig.getStringList("whitelist");
        List<String> networks = whitelistConfig.getStringList("networks");
        
        for (String ip : ips) {
            if (isValidIpAddress(ip)) {
                whitelistedIps.add(ip);
            }
        }
        
        for (String network : networks) {
            if (isValidCidrNotation(network)) {
                CIDREntry entry = parseCIDR(network);
                if (entry != null) {
                    whitelistedNetworks.add(entry);
                }
            }
        }
        
        logger.info("Loaded " + whitelistedIps.size() + " whitelisted IPs and " + 
                   whitelistedNetworks.size() + " whitelisted networks");
    }
    
    private void loadBlacklist() {
        blacklistedIps.clear();
        blacklistedNetworks.clear();
        
        if (!blacklistFile.exists()) {
            try {
                blacklistFile.createNewFile();
                FileConfiguration blacklistConfig = YamlConfiguration.loadConfiguration(blacklistFile);
                blacklistConfig.set("blacklist", new ArrayList<String>());
                blacklistConfig.set("networks", new ArrayList<String>());
                blacklistConfig.save(blacklistFile);
            } catch (IOException e) {
                logger.severe("Failed to create blacklist.yml: " + e.getMessage());
                return;
            }
        }
        
        FileConfiguration blacklistConfig = YamlConfiguration.loadConfiguration(blacklistFile);
        List<String> ips = blacklistConfig.getStringList("blacklist");
        List<String> networks = blacklistConfig.getStringList("networks");
        
        for (String ip : ips) {
            if (isValidIpAddress(ip)) {
                blacklistedIps.add(ip);
            }
        }
        
        for (String network : networks) {
            if (isValidCidrNotation(network)) {
                CIDREntry entry = parseCIDR(network);
                if (entry != null) {
                    blacklistedNetworks.add(entry);
                }
            }
        }
        
        logger.info("Loaded " + blacklistedIps.size() + " blacklisted IPs and " + 
                   blacklistedNetworks.size() + " blacklisted networks");
    }
    
    public void saveLists() {
        saveWhitelist();
        saveBlacklist();
    }
    
    private void saveWhitelist() {
        FileConfiguration whitelistConfig = YamlConfiguration.loadConfiguration(whitelistFile);
        whitelistConfig.set("whitelist", new ArrayList<>(whitelistedIps));
        
        List<String> networks = new ArrayList<>();
        for (CIDREntry entry : whitelistedNetworks) {
            networks.add(entry.getCidrNotation());
        }
        
        whitelistConfig.set("networks", networks);
        
        try {
            whitelistConfig.save(whitelistFile);
        } catch (IOException e) {
            logger.severe("Failed to save whitelist.yml: " + e.getMessage());
        }
    }
    
    private void saveBlacklist() {
        FileConfiguration blacklistConfig = YamlConfiguration.loadConfiguration(blacklistFile);
        blacklistConfig.set("blacklist", new ArrayList<>(blacklistedIps));
        
        List<String> networks = new ArrayList<>();
        for (CIDREntry entry : blacklistedNetworks) {
            networks.add(entry.getCidrNotation());
        }
        
        blacklistConfig.set("networks", networks);
        
        try {
            blacklistConfig.save(blacklistFile);
        } catch (IOException e) {
            logger.severe("Failed to save blacklist.yml: " + e.getMessage());
        }
    }
    
    private void startAutoSave() {
        if (!autoSaveEnabled) {
            return;
        }
        
        autoSaveTask = Bukkit.getScheduler().runTaskTimerAsynchronously(plugin, this::saveLists, 
            20 * 60 * autoSaveInterval, 20 * 60 * autoSaveInterval);
    }
    
    public boolean isWhitelisted(String ip) {
        if (!isValidIpAddress(ip)) {
            return false;
        }
        
        if (whitelistedIps.contains(ip)) {
            return true;
        }
        
        try {
            InetAddress address = InetAddress.getByName(ip);
            byte[] bytes = address.getAddress();
            
            for (CIDREntry entry : whitelistedNetworks) {
                if (entry.contains(bytes)) {
                    return true;
                }
            }
        } catch (Exception e) {
            return false;
        }
        
        return false;
    }
    
    public boolean isWhitelisted(InetAddress address) {
        return isWhitelisted(address.getHostAddress());
    }
    
    public boolean isBlacklisted(String ip) {
        if (!isValidIpAddress(ip)) {
            return blockByDefault;
        }
        
        if (blacklistedIps.contains(ip)) {
            return true;
        }
        
        try {
            InetAddress address = InetAddress.getByName(ip);
            byte[] bytes = address.getAddress();
            
            for (CIDREntry entry : blacklistedNetworks) {
                if (entry.contains(bytes)) {
                    return true;
                }
            }
        } catch (Exception e) {
            return blockByDefault;
        }
        
        return false;
    }
    
    public boolean isBlacklisted(InetAddress address) {
        return isBlacklisted(address.getHostAddress());
    }
    
    public boolean shouldBlock(InetAddress address) {
        if (address == null) {
            return blockByDefault;
        }
        
        String ip = address.getHostAddress();
        
        if (isWhitelisted(ip)) {
            return false;
        }
        
        if (isBlacklisted(ip)) {
            return true;
        }
        
        return blockByDefault;
    }
    
    public boolean addToWhitelist(String ip) {
        if (isValidIpAddress(ip)) {
            if (blacklistedIps.contains(ip)) {
                blacklistedIps.remove(ip);
            }
            
            boolean result = whitelistedIps.add(ip);
            if (result && autoSaveEnabled) {
                saveWhitelist();
            }
            return result;
        } else if (isValidCidrNotation(ip)) {
            CIDREntry entry = parseCIDR(ip);
            if (entry != null) {
                whitelistedNetworks.add(entry);
                if (autoSaveEnabled) {
                    saveWhitelist();
                }
                return true;
            }
        }
        
        return false;
    }
    
    public boolean removeFromWhitelist(String ip) {
        if (isValidIpAddress(ip)) {
            boolean result = whitelistedIps.remove(ip);
            if (result && autoSaveEnabled) {
                saveWhitelist();
            }
            return result;
        } else if (isValidCidrNotation(ip)) {
            CIDREntry entry = parseCIDR(ip);
            if (entry != null) {
                boolean result = whitelistedNetworks.removeIf(e -> e.getCidrNotation().equals(ip));
                if (result && autoSaveEnabled) {
                    saveWhitelist();
                }
                return result;
            }
        }
        
        return false;
    }
    
    public boolean addToBlacklist(String ip) {
        if (isValidIpAddress(ip)) {
            if (whitelistedIps.contains(ip)) {
                whitelistedIps.remove(ip);
            }
            
            boolean result = blacklistedIps.add(ip);
            if (result && autoSaveEnabled) {
                saveBlacklist();
            }
            return result;
        } else if (isValidCidrNotation(ip)) {
            CIDREntry entry = parseCIDR(ip);
            if (entry != null) {
                blacklistedNetworks.add(entry);
                if (autoSaveEnabled) {
                    saveBlacklist();
                }
                return true;
            }
        }
        
        return false;
    }
    
    public boolean removeFromBlacklist(String ip) {
        if (isValidIpAddress(ip)) {
            boolean result = blacklistedIps.remove(ip);
            if (result && autoSaveEnabled) {
                saveBlacklist();
            }
            return result;
        } else if (isValidCidrNotation(ip)) {
            CIDREntry entry = parseCIDR(ip);
            if (entry != null) {
                boolean result = blacklistedNetworks.removeIf(e -> e.getCidrNotation().equals(ip));
                if (result && autoSaveEnabled) {
                    saveBlacklist();
                }
                return result;
            }
        }
        
        return false;
    }
    
    public Set<String> getWhitelistedIps() {
        return new HashSet<>(whitelistedIps);
    }
    
    public Set<String> getBlacklistedIps() {
        return new HashSet<>(blacklistedIps);
    }
    
    public List<String> getWhitelistedNetworks() {
        List<String> networks = new ArrayList<>();
        for (CIDREntry entry : whitelistedNetworks) {
            networks.add(entry.getCidrNotation());
        }
        return networks;
    }
    
    public List<String> getBlacklistedNetworks() {
        List<String> networks = new ArrayList<>();
        for (CIDREntry entry : blacklistedNetworks) {
            networks.add(entry.getCidrNotation());
        }
        return networks;
    }
    
    public boolean isValidIpAddress(String ip) {
        if (ip == null || ip.isEmpty()) {
            return false;
        }
        return IP_PATTERN.matcher(ip).matches();
    }
    
    public boolean isValidCidrNotation(String cidr) {
        if (cidr == null || cidr.isEmpty()) {
            return false;
        }
        return CIDR_PATTERN.matcher(cidr).matches();
    }
    
    private CIDREntry parseCIDR(String cidr) {
        try {
            String[] parts = cidr.split("/");
            String ip = parts[0];
            int prefixLength = Integer.parseInt(parts[1]);
            
            if (prefixLength < 0 || prefixLength > 32) {
                return null;
            }
            
            InetAddress address = InetAddress.getByName(ip);
            byte[] bytes = address.getAddress();
            
            int mask = ~((1 << (32 - prefixLength)) - 1);
            
            byte[] networkBytes = new byte[4];
            networkBytes[0] = (byte) ((bytes[0] & 0xFF) & ((mask >> 24) & 0xFF));
            networkBytes[1] = (byte) ((bytes[1] & 0xFF) & ((mask >> 16) & 0xFF));
            networkBytes[2] = (byte) ((bytes[2] & 0xFF) & ((mask >> 8) & 0xFF));
            networkBytes[3] = (byte) ((bytes[3] & 0xFF) & (mask & 0xFF));
            
            return new CIDREntry(cidr, networkBytes, mask);
        } catch (Exception e) {
            return null;
        }
    }
    
    public static class CIDREntry {
        private final String cidrNotation;
        private final byte[] networkBytes;
        private final int mask;
        
        public CIDREntry(String cidrNotation, byte[] networkBytes, int mask) {
            this.cidrNotation = cidrNotation;
            this.networkBytes = networkBytes;
            this.mask = mask;
        }
        
        public String getCidrNotation() {
            return cidrNotation;
        }
        
        public boolean contains(byte[] address) {
            if (address.length != 4) {
                return false;
            }
            
            int ipInt = ((address[0] & 0xFF) << 24) |
                        ((address[1] & 0xFF) << 16) |
                        ((address[2] & 0xFF) << 8) |
                        (address[3] & 0xFF);
            
            int networkInt = ((networkBytes[0] & 0xFF) << 24) |
                             ((networkBytes[1] & 0xFF) << 16) |
                             ((networkBytes[2] & 0xFF) << 8) |
                             (networkBytes[3] & 0xFF);
            
            return (ipInt & mask) == networkInt;
        }
    }
}