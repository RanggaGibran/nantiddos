package id.nantiddos;

import id.nantiddos.analytics.SecurityMetrics;
import id.nantiddos.dashboard.SecurityConsole;
import id.nantiddos.network.ProxyIntegration;
import id.nantiddos.notification.NotificationManager;
import id.nantiddos.protection.AttackDetector;
import id.nantiddos.protection.ConnectionTracker;
import id.nantiddos.protection.ConnectionTracker.ConnectionType;
import id.nantiddos.protection.IPManager;
import id.nantiddos.protection.PacketMonitor;

import java.io.File;
import java.util.List;
import java.util.Map;
import java.util.logging.Logger;

import org.bukkit.Bukkit;
import org.bukkit.command.CommandSender;
import org.bukkit.configuration.file.FileConfiguration;
import org.bukkit.entity.Player;
import org.bukkit.event.EventHandler;
import org.bukkit.event.EventPriority;
import org.bukkit.event.Listener;
import org.bukkit.event.player.AsyncPlayerChatEvent;
import org.bukkit.event.player.AsyncPlayerPreLoginEvent;
import org.bukkit.event.player.PlayerCommandPreprocessEvent;
import org.bukkit.event.player.PlayerJoinEvent;
import org.bukkit.event.player.PlayerLoginEvent;
import org.bukkit.event.server.ServerListPingEvent;
import org.bukkit.plugin.java.JavaPlugin;

public class Nantiddos extends JavaPlugin implements Listener {
    private static Nantiddos instance;
    private final Logger logger = getLogger();
    
    private FileConfiguration config;
    private File configFile;
    private File dataFolder;
    
    private ConnectionTracker connectionTracker;
    private IPManager ipManager;
    private PacketMonitor packetMonitor;
    private SecurityConsole securityConsole;
    private AttackDetector attackDetector;
    private NotificationManager notificationManager;
    private SecurityMetrics securityMetrics;
    private ProxyIntegration proxyIntegration;
    
    private int maxConnectionsPerSecond;
    private int connectionTimeout;
    private boolean enableProtection;
    private boolean notifyAdmins;
    private String kickMessage;
    private String blacklistedMessage;
    private String packetFloodMessage;
    
    @Override
    public void onEnable() {
        instance = this;
        dataFolder = getDataFolder();
        
        if (!dataFolder.exists()) {
            dataFolder.mkdirs();
        }
        
        loadConfiguration();
        registerCommands();
        registerListeners();
        
        connectionTracker = new ConnectionTracker(this);
        ipManager = new IPManager(this);
        
        Bukkit.getScheduler().runTaskLater(this, () -> {
            packetMonitor = new PacketMonitor(this, connectionTracker, ipManager);
            logger.info("Packet analysis system initialized");
            
            attackDetector = new AttackDetector(this, connectionTracker, ipManager, packetMonitor);
            logger.info("Attack pattern recognition system initialized");
            
            notificationManager = new NotificationManager(this);
            logger.info("External notification system initialized");
            
            securityMetrics = new SecurityMetrics(this);
            logger.info("Analytics and reporting system initialized");
            
            securityConsole = new SecurityConsole(this, connectionTracker, ipManager, packetMonitor);
            logger.info("Security dashboard initialized");
            
            proxyIntegration = new ProxyIntegration(this);
            logger.info("Network protection system initialized");
        }, 40L);
        
        logger.info("NantiDDoS v" + getDescription().getVersion() + " enabled successfully");
        logger.info("Protection status: " + (enableProtection ? "ENABLED" : "DISABLED"));
    }
    
    @Override
    public void onDisable() {
        if (connectionTracker != null) {
            connectionTracker.shutdown();
        }
        
        if (ipManager != null) {
            ipManager.shutdown();
        }
        
        if (packetMonitor != null) {
            packetMonitor.shutdown();
        }
        
        if (attackDetector != null) {
            attackDetector.shutdown();
        }
        
        if (notificationManager != null) {
            notificationManager.shutdown();
        }
        
        if (securityMetrics != null) {
            securityMetrics.shutdown();
        }
        
        if (securityConsole != null) {
            securityConsole.shutdown();
        }
        
        if (proxyIntegration != null) {
            proxyIntegration.shutdown();
        }
        
        logger.info("NantiDDoS disabled");
        saveConfig();
    }
    
    public static Nantiddos getInstance() {
        return instance;
    }
    
    public NotificationManager getNotificationManager() {
        return notificationManager;
    }
    
    public ConnectionTracker getConnectionTracker() {
        return connectionTracker;
    }
    
    public IPManager getIpManager() {
        return ipManager;
    }
    
    public AttackDetector getAttackDetector() {
        return attackDetector;
    }
    
    public PacketMonitor getPacketMonitor() {
        return packetMonitor;
    }
    
    public SecurityMetrics getSecurityMetrics() {
        return securityMetrics;
    }
    
    public ProxyIntegration getProxyIntegration() {
        return proxyIntegration;
    }
    
    public boolean getEnableProtection() {
        return enableProtection;
    }

    public int getMaxConnectionsPerSecond() {
        return maxConnectionsPerSecond;
    }

    public int getConnectionTimeout() {
        return connectionTimeout;
    }
    
    private void loadConfiguration() {
        configFile = new File(dataFolder, "config.yml");
        
        if (!configFile.exists()) {
            saveDefaultConfig();
        }
        
        config = getConfig();
        
        maxConnectionsPerSecond = config.getInt("protection.max-connections-per-second", 3);
        connectionTimeout = config.getInt("protection.connection-timeout", 5000);
        enableProtection = config.getBoolean("protection.enabled", true);
        notifyAdmins = config.getBoolean("notifications.notify-admins", true);
        kickMessage = config.getString("messages.kick-message", "§c§lConnection throttled! Please wait before reconnecting.");
        blacklistedMessage = config.getString("messages.blacklisted-ip-message", "§c§lYour IP address is blacklisted from this server.");
        packetFloodMessage = config.getString("messages.packet-flood-message", "§c§lYou have been kicked for sending too many packets to the server.");
        
        if (!config.contains("network.server-id")) {
            config.set("network.server-id", "");
        }
        if (!config.contains("network.network-id")) {
            config.set("network.network-id", "default");
        }
        if (!config.contains("network.sync-interval-seconds")) {
            config.set("network.sync-interval-seconds", 30);
        }
        if (!config.contains("network.sync-blacklist")) {
            config.set("network.sync-blacklist", true);
        }
        if (!config.contains("network.sync-whitelist")) {
            config.set("network.sync-whitelist", true);
        }
        if (!config.contains("network.sync-attack-data")) {
            config.set("network.sync-attack-data", true);
        }
        if (!config.contains("network.master-server")) {
            config.set("network.master-server", false);
        }
        
        saveConfig();
    }
    
    private void registerCommands() {
        getCommand("nantiddos").setExecutor((sender, cmd, label, args) -> {
            if (!sender.hasPermission("nantiddos.admin")) {
                sender.sendMessage("§cYou don't have permission to use this command.");
                return true;
            }
            
            if (args.length == 0) {
                showHelp(sender);
                return true;
            }
            
            switch (args[0].toLowerCase()) {
                case "reload":
                    reloadConfiguration(sender);
                    break;
                case "status":
                    showStatus(sender);
                    break;
                case "enable":
                    toggleProtection(sender, true);
                    break;
                case "disable":
                    toggleProtection(sender, false);
                    break;
                case "clear":
                    clearData(sender);
                    break;
                case "whitelist":
                    handleWhitelistCommand(sender, args);
                    break;
                case "blacklist":
                    handleBlacklistCommand(sender, args);
                    break;
                case "packets":
                    handlePacketsCommand(sender, args);
                    break;
                case "network":
                    handleNetworkCommand(sender, args);
                    break;
                case "dashboard":
                case "gui":
                    if (!(sender instanceof Player)) {
                        sender.sendMessage("§cThis command can only be used by players.");
                        return true;
                    }
                    
                    if (securityConsole != null) {
                        securityConsole.openDashboard((Player) sender);
                    } else {
                        sender.sendMessage("§cSecurity dashboard is not initialized yet. Please try again later.");
                    }
                    break;
                case "analytics":
                    handleAnalyticsCommand(sender, args);
                    break;
                default:
                    showHelp(sender);
                    break;
            }
            
            return true;
        });
    }
    
    private void handleNetworkCommand(CommandSender sender, String[] args) {
        if (!sender.hasPermission("nantiddos.admin")) {
            sender.sendMessage("§cYou don't have permission to use this command.");
            return;
        }
        
        if (proxyIntegration == null) {
            sender.sendMessage("§cNetwork system is not initialized yet. Please try again later.");
            return;
        }
        
        if (args.length < 2) {
            sender.sendMessage("§6========== §eNantiDDoS Network Commands §6==========");
            sender.sendMessage("§e/nantiddos network status §7- Show network status");
            sender.sendMessage("§e/nantiddos network sync §7- Force synchronize data now");
            sender.sendMessage("§e/nantiddos network master <true|false> §7- Set this server as master");
            return;
        }
        
        switch (args[1].toLowerCase()) {
            case "status":
                sender.sendMessage("§6========== §eNetwork Status §6==========");
                sender.sendMessage("§eProxy Type: §f" + proxyIntegration.getProxyType());
                sender.sendMessage("§eProxy Enabled: §f" + proxyIntegration.isProxyEnabled());
                sender.sendMessage("§eServer ID: §f" + config.getString("network.server-id"));
                sender.sendMessage("§eNetwork ID: §f" + config.getString("network.network-id"));
                sender.sendMessage("§eIs Master: §f" + proxyIntegration.isMasterServer());
                sender.sendMessage("§eMaster Server ID: §f" + proxyIntegration.getMasterServerId());
                sender.sendMessage("§eNetwork Servers: §f" + proxyIntegration.getNetworkServers().size());
                break;
                
            case "sync":
                sender.sendMessage("§aForcing network data synchronization...");
                Bukkit.getScheduler().runTaskAsynchronously(this, () -> {
                    if (proxyIntegration.isMasterServer()) {
                        sender.sendMessage("§aBroadcasting data as master server...");
                    } else {
                        sender.sendMessage("§aSending data to master server...");
                    }
                });
                break;
                
            case "master":
                if (args.length < 3) {
                    sender.sendMessage("§cUsage: /nantiddos network master <true|false>");
                    return;
                }
                
                boolean setAsMaster = Boolean.parseBoolean(args[2]);
                config.set("network.master-server", setAsMaster);
                saveConfig();
                
                sender.sendMessage("§aServer master status set to: §e" + setAsMaster);
                sender.sendMessage("§aReload the plugin to apply this change: §e/nantiddos reload");
                break;
                
            default:
                sender.sendMessage("§cUnknown network subcommand. Try /nantiddos network");
                break;
        }
    }
    
    private void handleAnalyticsCommand(CommandSender sender, String[] args) {
        if (!sender.hasPermission("nantiddos.admin")) {
            sender.sendMessage("§cYou don't have permission to use this command.");
            return;
        }
        
        if (securityMetrics == null) {
            sender.sendMessage("§cAnalytics system is not initialized yet. Please try again later.");
            return;
        }
        
        if (args.length < 2) {
            sender.sendMessage("§6========== §eNantiDDoS Analytics §6==========");
            sender.sendMessage("§e/nantiddos analytics report daily §7- View today's security summary");
            sender.sendMessage("§e/nantiddos analytics report weekly §7- View this week's security summary");
            sender.sendMessage("§e/nantiddos analytics report custom <start> <end> §7- Generate a custom report");
            sender.sendMessage("§e/nantiddos analytics list §7- List available reports");
            return;
        }
        
        switch (args[1].toLowerCase()) {
            case "report":
                if (args.length < 3) {
                    sender.sendMessage("§cPlease specify the report type (daily, weekly, custom).");
                    return;
                }
                
                switch (args[2].toLowerCase()) {
                    case "daily":
                        showDailyAnalytics(sender);
                        break;
                    case "weekly":
                        showWeeklyAnalytics(sender);
                        break;
                    case "custom":
                        if (args.length < 5) {
                            sender.sendMessage("§cUsage: /nantiddos analytics report custom <start-date> <end-date>");
                            sender.sendMessage("§cDates should be in yyyy-MM-dd format.");
                            return;
                        }
                        String result = securityMetrics.generateCustomReport(args[3], args[4]);
                        sender.sendMessage("§e" + result);
                        break;
                    default:
                        sender.sendMessage("§cUnknown report type. Options: daily, weekly, custom");
                        break;
                }
                break;
            case "list":
                listReports(sender);
                break;
            default:
                sender.sendMessage("§cUnknown analytics subcommand. Try /nantiddos analytics");
                break;
        }
    }

    private void handlePacketsCommand(CommandSender sender, String[] args) {
        if (packetMonitor == null) {
            sender.sendMessage("§cPacket monitoring system is not initialized yet.");
            return;
        }
        
        if (args.length < 2) {
            sender.sendMessage("§c§lUsage: §e/nantiddos packets <info|kick> [player]");
            return;
        }
        
        switch (args[1].toLowerCase()) {
            case "info":
                sender.sendMessage("§6========== §ePacket Analysis Info §6==========");
                sender.sendMessage("§eMonitoring enabled: §a" + (packetMonitor.isPacketMonitoringFullyAvailable() ? "Yes" : "Limited (No ProtocolLib)"));
                sender.sendMessage("§eActive monitoring sessions: §a" + packetMonitor.getActivePacketMonitoringSessions());
                sender.sendMessage("§eSuspicious packet sources: §c" + packetMonitor.getSuspiciousPacketSources());
                break;
                
            case "kick":
                if (args.length < 3) {
                    sender.sendMessage("§c§lUsage: §e/nantiddos packets kick <player>");
                    return;
                }
                
                Player target = Bukkit.getPlayer(args[2]);
                if (target == null) {
                    sender.sendMessage("§cPlayer not found: §e" + args[2]);
                    return;
                }
                
                target.kickPlayer(packetFloodMessage);
                sender.sendMessage("§aKicked player §e" + target.getName() + " §afor packet flooding");
                break;
                
            default:
                sender.sendMessage("§c§lUnknown subcommand: §e" + args[1]);
                sender.sendMessage("§c§lUsage: §e/nantiddos packets <info|kick> [player]");
                break;
        }
    }

    private void showDailyAnalytics(CommandSender sender) {
        Map<String, Object> data = securityMetrics.generateAnalyticsData();
        
        sender.sendMessage("§6========== §eNantiDDoS Daily Analytics §6==========");
        sender.sendMessage("§eCurrent Threat Level: §c" + data.get("currentThreatLevel") + " (" + data.get("currentAlertLevel") + ")");
        sender.sendMessage("§eActive Attack Sources: §c" + data.get("activeAttackSources"));
        
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> dailyData = (List<Map<String, Object>>) data.get("dailyData");
        if (dailyData != null && !dailyData.isEmpty()) {
            Map<String, Object> today = dailyData.get(0);
            sender.sendMessage("§eToday's Statistics:");
            sender.sendMessage("§7- Average Connections: §f" + today.get("avgConnections"));
            sender.sendMessage("§7- Maximum Connections: §f" + today.get("maxConnections"));
            sender.sendMessage("§7- Maximum Threat Level: §f" + today.get("maxThreat"));
            sender.sendMessage("§7- Attack Count: §f" + today.get("attackCount"));
        }
        
        sender.sendMessage("§eDetailed reports available in plugins/NantiDDoS/reports/");
    }

    private void showWeeklyAnalytics(CommandSender sender) {
        Map<String, Object> data = securityMetrics.generateAnalyticsData();
        
        sender.sendMessage("§6========== §eNantiDDoS Weekly Analytics §6==========");
        sender.sendMessage("§eTotal Connections: §f" + data.get("totalConnections"));
        sender.sendMessage("§eMax Connections: §f" + data.get("maxConnections"));
        sender.sendMessage("§eTotal Attacks: §c" + data.get("totalAttacks"));
        sender.sendMessage("§eHigh Severity Attacks: §c" + data.get("highSeverityAttacks"));
        
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> attackTypes = (List<Map<String, Object>>) data.get("attackTypes");
        if (attackTypes != null && !attackTypes.isEmpty()) {
            sender.sendMessage("§eAttack Types:");
            for (Map<String, Object> type : attackTypes) {
                sender.sendMessage("§7- " + type.get("type") + ": §c" + type.get("count"));
            }
        }
        
        sender.sendMessage("§eDetailed reports available in plugins/NantiDDoS/reports/");
    }

    private void listReports(CommandSender sender) {
        List<Map<String, String>> reports = securityMetrics.getReportHistory();
        
        sender.sendMessage("§6========== §eNantiDDoS Report History §6==========");
        if (reports.isEmpty()) {
            sender.sendMessage("§7No reports available.");
            return;
        }
        
        int count = 0;
        for (Map<String, String> report : reports) {
            if (count++ >= 10) {
                sender.sendMessage("§7... and " + (reports.size() - 10) + " more");
                break;
            }
            
            String fileName = report.getOrDefault("fileName", report.getOrDefault("path", "Unknown"));
            if (fileName.contains("\\")) {
                fileName = fileName.substring(fileName.lastIndexOf('\\') + 1);
            }
            String date = report.getOrDefault("date", report.getOrDefault("timestamp", "Unknown"));
            String size = report.getOrDefault("size", "Unknown");
            
            sender.sendMessage("§e" + fileName + " §7- §f" + date + " §7(§f" + size + "§7)");
        }
        
        sender.sendMessage("§7Reports are stored in plugins/NantiDDoS/reports/");
    }
    
    private void handleWhitelistCommand(CommandSender sender, String[] args) {
        if (args.length < 2) {
            sender.sendMessage("§c§lUsage: §e/nantiddos whitelist <add|remove|list> [ip]");
            return;
        }
        
        switch (args[1].toLowerCase()) {
            case "add":
                if (args.length < 3) {
                    sender.sendMessage("§c§lUsage: §e/nantiddos whitelist add <ip>");
                    return;
                }
                
                String ipToWhitelist = args[2];
                if (ipManager.addToWhitelist(ipToWhitelist)) {
                    sender.sendMessage("§a" + ipToWhitelist + " added to whitelist.");
                } else {
                    sender.sendMessage("§cInvalid IP or CIDR notation: " + ipToWhitelist);
                }
                break;
                
            case "remove":
                if (args.length < 3) {
                    sender.sendMessage("§c§lUsage: §e/nantiddos whitelist remove <ip>");
                    return;
                }
                
                String ipToRemove = args[2];
                if (ipManager.removeFromWhitelist(ipToRemove)) {
                    sender.sendMessage("§a" + ipToRemove + " removed from whitelist.");
                } else {
                    sender.sendMessage("§c" + ipToRemove + " not found in whitelist.");
                }
                break;
                
            case "list":
                sender.sendMessage("§6========== §eWhitelisted IPs §6==========");
                for (String ip : ipManager.getWhitelistedIps()) {
                    sender.sendMessage("§f- " + ip);
                }
                
                sender.sendMessage("§6========== §eWhitelisted Networks §6==========");
                for (String network : ipManager.getWhitelistedNetworks()) {
                    sender.sendMessage("§f- " + network);
                }
                break;
                
            default:
                sender.sendMessage("§c§lUnknown subcommand: §e" + args[1]);
                sender.sendMessage("§c§lUsage: §e/nantiddos whitelist <add|remove|list> [ip]");
                break;
        }
    }
    
    private void handleBlacklistCommand(CommandSender sender, String[] args) {
        if (args.length < 2) {
            sender.sendMessage("§c§lUsage: §e/nantiddos blacklist <add|remove|list> [ip]");
            return;
        }
        
        switch (args[1].toLowerCase()) {
            case "add":
                if (args.length < 3) {
                    sender.sendMessage("§c§lUsage: §e/nantiddos blacklist add <ip>");
                    return;
                }
                
                String ipToBlacklist = args[2];
                if (ipManager.addToBlacklist(ipToBlacklist)) {
                    sender.sendMessage("§a" + ipToBlacklist + " added to blacklist.");
                } else {
                    sender.sendMessage("§cInvalid IP or CIDR notation: " + ipToBlacklist);
                }
                break;
                
            case "remove":
                if (args.length < 3) {
                    sender.sendMessage("§c§lUsage: §e/nantiddos blacklist remove <ip>");
                    return;
                }
                
                String ipToRemove = args[2];
                if (ipManager.removeFromBlacklist(ipToRemove)) {
                    sender.sendMessage("§a" + ipToRemove + " removed from blacklist.");
                } else {
                    sender.sendMessage("§c" + ipToRemove + " not found in blacklist.");
                }
                break;
                
            case "list":
                sender.sendMessage("§6========== §eBlacklisted IPs §6==========");
                for (String ip : ipManager.getBlacklistedIps()) {
                    sender.sendMessage("§f- " + ip);
                }
                
                sender.sendMessage("§6========== §eBlacklisted Networks §6==========");
                for (String network : ipManager.getBlacklistedNetworks()) {
                    sender.sendMessage("§f- " + network);
                }
                break;
                
            default:
                sender.sendMessage("§c§lUnknown subcommand: §e" + args[1]);
                sender.sendMessage("§c§lUsage: §e/nantiddos blacklist <add|remove|list> [ip]");
                break;
        }
    }
    
    private void registerListeners() {
        getServer().getPluginManager().registerEvents(this, this);
    }
    
    private void showHelp(CommandSender sender) {
        sender.sendMessage("§6========== §eNantiDDoS Help §6==========");
        sender.sendMessage("§e/nantiddos status §7- Show current protection status");
        sender.sendMessage("§e/nantiddos reload §7- Reload configuration");
        sender.sendMessage("§e/nantiddos enable §7- Enable protection");
        sender.sendMessage("§e/nantiddos disable §7- Disable protection");
        sender.sendMessage("§e/nantiddos clear §7- Clear connection data");
        sender.sendMessage("§e/nantiddos whitelist <add|remove|list> [ip] §7- Manage whitelist");
        sender.sendMessage("§e/nantiddos blacklist <add|remove|list> [ip] §7- Manage blacklist");
        sender.sendMessage("§e/nantiddos packets <info|kick> [player] §7- Packet analysis commands");
        sender.sendMessage("§e/nantiddos network §7- Network-wide protection commands");
        sender.sendMessage("§e/nantiddos dashboard §7- Open security dashboard GUI");
        sender.sendMessage("§e/nantiddos analytics §7- View security analytics");
    }
    
    private void reloadConfiguration(CommandSender sender) {
        reloadConfig();
        loadConfiguration();
        
        if (connectionTracker != null) {
            connectionTracker.loadConfig();
        }
        
        if (ipManager != null) {
            ipManager.loadConfig();
        }
        
        if (packetMonitor != null) {
            packetMonitor.loadConfig();
        }
        
        if (attackDetector != null) {
            attackDetector.loadConfig();
        }
        
        if (notificationManager != null) {
            notificationManager.loadConfig();
        }
        
        if (securityMetrics != null) {
            securityMetrics.loadConfig();
        }
        
        if (proxyIntegration != null) {
            proxyIntegration.loadConfig();
        }
        
        sender.sendMessage("§aNantiDDoS configuration reloaded successfully!");
        
        if (notificationManager != null && notificationManager.isEnabled()) {
            String actor = sender instanceof Player ? sender.getName() : "Console";
            notificationManager.notifyConfigChanged(actor);
        }
    }
    
    private void showStatus(CommandSender sender) {
        sender.sendMessage("§6========== §eNantiDDoS Status §6==========");
        sender.sendMessage("§eProtection: " + (enableProtection ? "§aENABLED" : "§cDISABLED"));
        sender.sendMessage("§eMax Connections/Second: §a" + maxConnectionsPerSecond);
        sender.sendMessage("§eConnection Timeout: §a" + connectionTimeout + "ms");
        
        if (connectionTracker != null) {
            sender.sendMessage("§eTracked IPs: §a" + connectionTracker.getConnectionsCount());
            sender.sendMessage("§eSuspicious IPs: §c" + connectionTracker.getSuspiciousConnectionsCount());
        }
        
        if (ipManager != null) {
            sender.sendMessage("§eWhitelisted IPs: §a" + ipManager.getWhitelistedIps().size());
            sender.sendMessage("§eWhitelisted Networks: §a" + ipManager.getWhitelistedNetworks().size());
            sender.sendMessage("§eBlacklisted IPs: §c" + ipManager.getBlacklistedIps().size());
            sender.sendMessage("§eBlacklisted Networks: §c" + ipManager.getBlacklistedNetworks().size());
        }
        
        if (packetMonitor != null) {
            sender.sendMessage("§ePacket Analysis: " + (packetMonitor.isPacketMonitoringFullyAvailable() ? "§aFull" : "§eBasic"));
            sender.sendMessage("§eSuspicious Packet Sources: §c" + packetMonitor.getSuspiciousPacketSources());
        } else {
            sender.sendMessage("§ePacket Analysis: §cNot Initialized");
        }
        
        if (attackDetector != null) {
            sender.sendMessage("§eThreat Level: " + attackDetector.getSystemAlertLevel().getColor() + 
                              attackDetector.getSystemAlertLevel().name() + " (" + attackDetector.getCurrentThreatLevel() + "/100)");
            sender.sendMessage("§eActive Attack Sources: §c" + attackDetector.getActiveAttackSourcesCount());
        } else {
            sender.sendMessage("§eAttack Detection: §cNot Initialized");
        }
        
        if (securityMetrics != null) {
            Map<String, Object> data = securityMetrics.generateAnalyticsData();
            sender.sendMessage("§eAttacks (Last 7 Days): §c" + data.get("totalAttacks"));
            sender.sendMessage("§eHigh Severity Attacks: §c" + data.get("highSeverityAttacks"));
        } else {
            sender.sendMessage("§eAnalytics: §cNot Initialized");
        }
        
        if (proxyIntegration != null) {
            sender.sendMessage("§eNetwork Mode: " + (proxyIntegration.isProxyEnabled() ? "§aEnabled (" + proxyIntegration.getProxyType() + ")" : "§cDisabled"));
            sender.sendMessage("§eServer Role: " + (proxyIntegration.isMasterServer() ? "§aMaster" : "§eNode"));
            sender.sendMessage("§eNetwork Servers: §a" + proxyIntegration.getNetworkServers().size());
        } else {
            sender.sendMessage("§eNetwork Mode: §cNot Initialized");
        }
    }
    
    private void toggleProtection(CommandSender sender, boolean enable) {
        enableProtection = enable;
        config.set("protection.enabled", enable);
        saveConfig();
        
        if (connectionTracker != null) {
            connectionTracker.enableProtection(enable);
        }
        
        if (packetMonitor != null) {
            packetMonitor.enableProtection(enable);
        }
        
        if (attackDetector != null) {
            attackDetector.enableProtection(enable);
        }
        
        if (proxyIntegration != null) {
            proxyIntegration.enableProtection(enable);
        }
        
        sender.sendMessage("§aNantiDDoS protection " + (enable ? "enabled" : "disabled") + "!");
        
        if (notificationManager != null && notificationManager.isEnabled()) {
            String actor = sender instanceof Player ? sender.getName() : "Console";
            notificationManager.notifyProtectionToggled(enable, actor);
        }
    }
    
    private void clearData(CommandSender sender) {
        if (connectionTracker != null) {
            connectionTracker.clearData();
        }
        
        sender.sendMessage("§aConnection data cleared!");
    }
    
    @EventHandler(priority = EventPriority.LOWEST)
    public void onServerPing(ServerListPingEvent event) {
        if (!enableProtection) return;
        
        if (ipManager != null && ipManager.isBlacklisted(event.getAddress())) {
            event.setMaxPlayers(0);
            event.setMotd("§c§lYou are blacklisted from this server.");
            return;
        }
        
        if (connectionTracker != null) {
            connectionTracker.trackConnection(event.getAddress(), ConnectionType.SERVER_PING);
            
            if (connectionTracker.shouldThrottleConnection(event.getAddress())) {
                event.setMaxPlayers(0);
                event.setMotd("§c§lSlow down! Connection throttled.");
            }
        }
    }
    
    @EventHandler(priority = EventPriority.LOWEST)
    public void onPlayerPreLogin(AsyncPlayerPreLoginEvent event) {
        if (!enableProtection) return;
        
        if (ipManager != null && ipManager.isBlacklisted(event.getAddress())) {
            event.disallow(AsyncPlayerPreLoginEvent.Result.KICK_BANNED, blacklistedMessage);
            logger.warning("Blocked login from blacklisted IP: " + event.getAddress().getHostAddress());
            return;
        }
        
        if (connectionTracker != null) {
            connectionTracker.trackConnection(event.getAddress(), ConnectionType.LOGIN_ATTEMPT);
            
            if (connectionTracker.shouldThrottleConnection(event.getAddress())) {
                event.disallow(AsyncPlayerPreLoginEvent.Result.KICK_OTHER, kickMessage);
                notifyAdmins("§c[NantiDDoS] §eBlocked connection attempt from §c" + 
                            event.getAddress().getHostAddress() + " §e(rate limit exceeded)");
            }
        }
    }
    
    @EventHandler(priority = EventPriority.MONITOR)
    public void onPlayerLogin(PlayerLoginEvent event) {
        if (!enableProtection || event.getResult() != PlayerLoginEvent.Result.ALLOWED) return;
        
        if (connectionTracker != null) {
            connectionTracker.registerSuccessfulLogin(event.getAddress().getHostAddress());
        }
    }
    
    @EventHandler(priority = EventPriority.MONITOR)
    public void onPlayerJoin(PlayerJoinEvent event) {
        Player player = event.getPlayer();
        
        if (connectionTracker != null) {
            connectionTracker.registerPlayerConnection(player.getUniqueId(), 
                player.getAddress().getAddress());
        }
        
        if (player.hasPermission("nantiddos.admin") && notifyAdmins) {
            Bukkit.getScheduler().runTaskLater(this, () -> {
                if (attackDetector != null && attackDetector.getCurrentThreatLevel() >= 50) {
                    player.sendMessage("§c[NantiDDoS] §eWARNING: Current threat level is §c" + 
                                      attackDetector.getSystemAlertLevel().name() + " §e(" + 
                                      attackDetector.getCurrentThreatLevel() + "/100)");
                }
                
                if (connectionTracker != null && connectionTracker.getSuspiciousConnectionsCount() > 5) {
                    player.sendMessage("§c[NantiDDoS] §eThere are §c" + 
                                      connectionTracker.getSuspiciousConnectionsCount() + 
                                      " §esuspicious IPs currently tracked.");
                }
            }, 20L);
        }
    }
    
    @EventHandler(priority = EventPriority.MONITOR)
    public void onPlayerChat(AsyncPlayerChatEvent event) {
        if (!enableProtection || event.isCancelled()) return;
        
        if (connectionTracker != null && event.getPlayer().getAddress() != null) {
            connectionTracker.trackConnection(event.getPlayer().getAddress().getAddress(), 
                ConnectionType.CHAT_MESSAGE);
        }
    }
    
    @EventHandler(priority = EventPriority.MONITOR)
    public void onPlayerCommand(PlayerCommandPreprocessEvent event) {
        if (!enableProtection || event.isCancelled()) return;
        
        if (connectionTracker != null && event.getPlayer().getAddress() != null) {
            connectionTracker.trackConnection(event.getPlayer().getAddress().getAddress(), 
                ConnectionType.COMMAND);
        }
    }
    
    private void notifyAdmins(String message) {
        if (!notifyAdmins) return;
        
        for (Player player : Bukkit.getOnlinePlayers()) {
            if (player.hasPermission("nantiddos.admin")) {
                player.sendMessage(message);
            }
        }
    }
}
