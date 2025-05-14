package id.nantiddos;

import id.nantiddos.protection.ConnectionTracker;
import id.nantiddos.protection.ConnectionTracker.ConnectionType;

import java.io.File;
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
    
    private int maxConnectionsPerSecond;
    private int connectionTimeout;
    private boolean enableProtection;
    private boolean notifyAdmins;
    private String kickMessage;
    
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
        
        logger.info("NantiDDoS v" + getDescription().getVersion() + " enabled successfully");
        logger.info("Protection status: " + (enableProtection ? "ENABLED" : "DISABLED"));
    }
    
    @Override
    public void onDisable() {
        if (connectionTracker != null) {
            connectionTracker.shutdown();
        }
        
        logger.info("NantiDDoS disabled");
        saveConfig();
    }
    
    public static Nantiddos getInstance() {
        return instance;
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
                default:
                    showHelp(sender);
                    break;
            }
            
            return true;
        });
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
    }
    
    private void reloadConfiguration(CommandSender sender) {
        reloadConfig();
        loadConfiguration();
        
        if (connectionTracker != null) {
            connectionTracker.loadConfig();
        }
        
        sender.sendMessage("§aNantiDDoS configuration reloaded successfully!");
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
    }
    
    private void toggleProtection(CommandSender sender, boolean enable) {
        enableProtection = enable;
        config.set("protection.enabled", enable);
        saveConfig();
        
        if (connectionTracker != null) {
            connectionTracker.enableProtection(enable);
        }
        
        sender.sendMessage("§aNantiDDoS protection " + (enable ? "enabled" : "disabled") + "!");
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
        
        if (connectionTracker != null) {
            connectionTracker.trackConnection(event.getAddress(), ConnectionType.SERVER_PING);
            
            if (connectionTracker.shouldThrottleConnection(event.getAddress())) {
                // Throttle by setting max players to 0 and/or a custom MOTD
                event.setMaxPlayers(0);
                event.setMotd("§c§lConnection throttled! Please wait before reconnecting.");
            }
        }
    }
    
    @EventHandler(priority = EventPriority.LOWEST)
    public void onPlayerPreLogin(AsyncPlayerPreLoginEvent event) {
        if (!enableProtection) return;
        
        if (connectionTracker != null) {
            connectionTracker.trackConnection(event.getAddress(), ConnectionType.LOGIN_ATTEMPT);
            
            if (connectionTracker.shouldThrottleConnection(event.getAddress())) {
                event.disallow(AsyncPlayerPreLoginEvent.Result.KICK_OTHER, kickMessage);
                notifyAdmins("§c[NantiDDoS] §eBlocked connection attempt from §c" + 
                            event.getAddress().getHostAddress() + " §e(rate limit exceeded)");
                logger.warning("Blocked connection from " + event.getAddress().getHostAddress() + 
                              " (rate limit exceeded)");
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
                player.sendMessage("§a[NantiDDoS] §eProtection is currently " + 
                    (enableProtection ? "§aENABLED" : "§cDISABLED"));
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
