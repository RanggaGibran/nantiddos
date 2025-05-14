package id.nantiddos.dashboard;

import id.nantiddos.Nantiddos;
import id.nantiddos.analytics.SecurityMetrics;
import id.nantiddos.protection.AttackDetector;
import id.nantiddos.protection.AttackDetector.AlertLevel;
import id.nantiddos.protection.AttackDetector.AttackType;
import id.nantiddos.protection.ConnectionTracker;
import id.nantiddos.protection.IPManager;
import id.nantiddos.protection.PacketMonitor;
import id.nantiddos.proxy.ProxyIntegration;

import java.text.SimpleDateFormat;
import java.time.LocalDate;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.logging.Logger;
import java.util.stream.Collectors;

import org.bukkit.Bukkit;
import org.bukkit.ChatColor;
import org.bukkit.Material;
import org.bukkit.Sound;
import org.bukkit.entity.Player;
import org.bukkit.event.EventHandler;
import org.bukkit.event.Listener;
import org.bukkit.event.inventory.InventoryClickEvent;
import org.bukkit.event.player.AsyncPlayerChatEvent;
import org.bukkit.event.player.PlayerQuitEvent;
import org.bukkit.inventory.Inventory;
import org.bukkit.inventory.ItemStack;
import org.bukkit.inventory.meta.ItemMeta;
import org.bukkit.scheduler.BukkitTask;

public class SecurityConsole implements Listener {
    private final Nantiddos plugin;
    private final Logger logger;
    private final ConnectionTracker connectionTracker;
    private final IPManager ipManager;
    private final PacketMonitor packetMonitor;
    private final SecurityMetrics securityMetrics;
    private final AttackDetector attackDetector;
    
    private final Map<UUID, Inventory> activeConsoles = new HashMap<>();
    private final Map<UUID, String> playerPages = new HashMap<>();
    private final Map<UUID, String> ipInspections = new HashMap<>();
    private final Map<UUID, Integer> analyticsPages = new HashMap<>();
    private final Map<UUID, String> reportViewers = new HashMap<>();
    private final SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
    private final DateTimeFormatter dateOnlyFormat = DateTimeFormatter.ofPattern("yyyy-MM-dd");
    
    private BukkitTask refreshTask;
    private boolean enabled = true;
    
    public SecurityConsole(Nantiddos plugin, ConnectionTracker connectionTracker, IPManager ipManager, PacketMonitor packetMonitor) {
        this.plugin = plugin;
        this.logger = plugin.getLogger();
        this.connectionTracker = connectionTracker;
        this.ipManager = ipManager;
        this.packetMonitor = packetMonitor;
        this.securityMetrics = plugin.getSecurityMetrics();
        this.attackDetector = plugin.getAttackDetector();
        
        Bukkit.getPluginManager().registerEvents(this, plugin);
        startRefreshTask();
    }
    
    public void openDashboard(Player player) {
        if (!player.hasPermission("nantiddos.admin")) {
            player.sendMessage(ChatColor.RED + "You don't have permission to access the security dashboard.");
            return;
        }
        
        playerPages.put(player.getUniqueId(), "main");
        Inventory dashboard = createMainDashboard(player);
        player.openInventory(dashboard);
        activeConsoles.put(player.getUniqueId(), dashboard);
        
        player.playSound(player.getLocation(), Sound.BLOCK_NOTE_BLOCK_PLING, 1.0f, 1.5f);
    }
    
    public void shutdown() {
        if (refreshTask != null && !refreshTask.isCancelled()) {
            refreshTask.cancel();
        }
        
        activeConsoles.clear();
        playerPages.clear();
        ipInspections.clear();
    }
    
    private void startRefreshTask() {
        refreshTask = Bukkit.getScheduler().runTaskTimer(plugin, () -> {
            for (Player player : Bukkit.getOnlinePlayers()) {
                if (activeConsoles.containsKey(player.getUniqueId())) {
                    refreshPlayerConsole(player);
                }
            }
        }, 100L, 100L);
    }
    
    private void refreshPlayerConsole(Player player) {
        if (!player.isOnline()) return;
        
        String page = playerPages.get(player.getUniqueId());
        if (page == null) return;
        
        switch (page) {
            case "main":
                updateMainDashboard(player);
                break;
            case "analytics":
                int subPage = analyticsPages.getOrDefault(player.getUniqueId(), 0);
                openAnalyticsPage(player, subPage);
                break;
            case "reports":
                openReportsPage(player, 0);
                break;
            case "attackTypes":
                openAttackTypesPage(player);
                break;
            case "threatMap":
                openThreatMapPage(player);
                break;
            case "reportView":
                String reportPath = reportViewers.get(player.getUniqueId());
                if (reportPath != null) {
                    openReportViewPage(player, reportPath);
                }
                break;
            case "network":
                openNetworkPage(player);
                break;
        }
    }
    
    private Inventory createMainDashboard(Player player) {
        Inventory inventory = Bukkit.createInventory(null, 54, "§8§lNantiDDoS Security Dashboard");
        
        Map<String, Object> analyticsData = securityMetrics != null ? 
            securityMetrics.generateAnalyticsData() : new HashMap<>();
        
        ItemStack status = createGuiItem(Material.BEACON, "§e§lServer Protection Status", 
            "§7Protection: " + (plugin.getEnableProtection() ? "§aENABLED" : "§cDISABLED"),
            "§7Max Connections/sec: §f" + plugin.getMaxConnectionsPerSecond(),
            "§7Timeout: §f" + plugin.getConnectionTimeout() + " ms");
        inventory.setItem(4, status);
        
        ItemStack connectionsButton = createGuiItem(Material.COMPASS, "§e§lConnections Monitor", 
            "§7View and manage active connections",
            "§7Total tracked IPs: §f" + connectionTracker.getConnectionsCount(),
            "§7Suspicious IPs: §c" + connectionTracker.getSuspiciousConnectionsCount(),
            "",
            "§eClick to view details");
        inventory.setItem(19, connectionsButton);
        
        ItemStack whitelistButton = createGuiItem(Material.PAPER, "§a§lWhitelist Manager", 
            "§7View and manage whitelisted IPs",
            "§7Whitelisted IPs: §f" + ipManager.getWhitelistedIps().size(),
            "§7Whitelisted Networks: §f" + ipManager.getWhitelistedNetworks().size(),
            "",
            "§eClick to manage");
        inventory.setItem(21, whitelistButton);
        
        ItemStack blacklistButton = createGuiItem(Material.BARRIER, "§c§lBlacklist Manager", 
            "§7View and manage blacklisted IPs",
            "§7Blacklisted IPs: §f" + ipManager.getBlacklistedIps().size(),
            "§7Blacklisted Networks: §f" + ipManager.getBlacklistedNetworks().size(),
            "",
            "§eClick to manage");
        inventory.setItem(23, blacklistButton);
        
        ItemStack packetButton = createGuiItem(Material.REPEATER, "§b§lPacket Analysis", 
            "§7View packet monitoring data",
            "§7Monitoring status: " + (packetMonitor.isPacketMonitoringFullyAvailable() ? "§aFull" : "§eBasic"),
            "§7Active sessions: §f" + packetMonitor.getActivePacketMonitoringSessions(),
            "§7Suspicious sources: §c" + packetMonitor.getSuspiciousPacketSources(),
            "",
            "§eClick to view details");
        inventory.setItem(25, packetButton);
        
        AlertLevel threatLevel = attackDetector.getSystemAlertLevel();
        Material threatMaterial;
        switch (threatLevel) {
            case CRITICAL: threatMaterial = Material.RED_CONCRETE; break;
            case HIGH: threatMaterial = Material.ORANGE_CONCRETE; break;
            case MEDIUM: threatMaterial = Material.YELLOW_CONCRETE; break;
            case LOW: threatMaterial = Material.LIME_CONCRETE; break;
            default: threatMaterial = Material.GREEN_CONCRETE;
        }
        
        String threatLevelDisplay = threatLevel.getColor() + threatLevel.name();
        
        ItemStack threatStatus = createGuiItem(threatMaterial, "§e§lThreat Status", 
            "§7Current Threat Level: " + threatLevelDisplay,
            "§7Threat Score: §f" + attackDetector.getCurrentThreatLevel() + "/100",
            "§7Active Attack Sources: §c" + attackDetector.getActiveAttackSourcesCount(),
            "§7Recent Attacks: §c" + attackDetector.getRecentAttacks().size());
        inventory.setItem(31, threatStatus);
        
        ItemStack analyticsButton = createGuiItem(Material.KNOWLEDGE_BOOK, "§d§lSecurity Analytics", 
            "§7View detailed security analytics",
            "§7Attacks (7d): §c" + analyticsData.getOrDefault("totalAttacks", "N/A"),
            "§7High Severity: §c" + analyticsData.getOrDefault("highSeverityAttacks", "N/A"),
            "",
            "§eClick to view analytics dashboard");
        inventory.setItem(40, analyticsButton);
        
        ItemStack networkButton = createGuiItem(Material.NETHER_STAR, "§d§lNetwork Protection", 
            "§7Manage cross-server protection",
            "§7Status: " + (plugin.isNetworkProtectionEnabled() ? "§aENABLED" : "§cDISABLED"),
            "",
            "§eClick to manage");
        inventory.setItem(42, networkButton);
        
        ItemStack kickButton = createGuiItem(Material.REDSTONE_BLOCK, "§c§lKick Suspicious Players", 
            "§7Kick players with suspicious packet activity",
            "§7This will immediately remove players",
            "§7with high threat scores from the server",
            "",
            "§c§lWARNING: Use with caution!");
        inventory.setItem(45, kickButton);
        
        ItemStack configButton = createGuiItem(Material.COMMAND_BLOCK, "§6§lConfiguration", 
            "§7Modify protection settings",
            "§7Toggle protection, adjust thresholds,",
            "§7and manage other configuration options",
            "",
            "§eClick to configure");
        inventory.setItem(49, configButton);
        
        ItemStack exitButton = createGuiItem(Material.OAK_DOOR, "§7§lClose Dashboard", 
            "§7Exit the security dashboard");
        inventory.setItem(53, exitButton);
        
        fillEmptySlots(inventory);
        return inventory;
    }
    
    private void updateMainDashboard(Player player) {
        Inventory inventory = activeConsoles.get(player.getUniqueId());
        if (inventory == null) return;
        
        Map<String, Object> analyticsData = securityMetrics != null ? 
            securityMetrics.generateAnalyticsData() : new HashMap<>();
        
        AlertLevel threatLevel = attackDetector.getSystemAlertLevel();
        Material threatMaterial;
        switch (threatLevel) {
            case CRITICAL: threatMaterial = Material.RED_CONCRETE; break;
            case HIGH: threatMaterial = Material.ORANGE_CONCRETE; break;
            case MEDIUM: threatMaterial = Material.YELLOW_CONCRETE; break;
            case LOW: threatMaterial = Material.LIME_CONCRETE; break;
            default: threatMaterial = Material.GREEN_CONCRETE;
        }
        
        String threatLevelDisplay = threatLevel.getColor() + threatLevel.name();
        
        ItemStack threatStatus = createGuiItem(threatMaterial, "§e§lThreat Status", 
            "§7Current Threat Level: " + threatLevelDisplay,
            "§7Threat Score: §f" + attackDetector.getCurrentThreatLevel() + "/100",
            "§7Active Attack Sources: §c" + attackDetector.getActiveAttackSourcesCount(),
            "§7Recent Attacks: §c" + attackDetector.getRecentAttacks().size());
        inventory.setItem(31, threatStatus);
        
        ItemStack analyticsButton = createGuiItem(Material.KNOWLEDGE_BOOK, "§d§lSecurity Analytics", 
            "§7View detailed security analytics",
            "§7Attacks (7d): §c" + analyticsData.getOrDefault("totalAttacks", "N/A"),
            "§7High Severity: §c" + analyticsData.getOrDefault("highSeverityAttacks", "N/A"),
            "",
            "§eClick to view analytics dashboard");
        inventory.setItem(40, analyticsButton);
        
        ItemStack networkButton = createGuiItem(Material.NETHER_STAR, "§d§lNetwork Protection", 
            "§7Manage cross-server protection",
            "§7Status: " + (plugin.isNetworkProtectionEnabled() ? "§aENABLED" : "§cDISABLED"),
            "",
            "§eClick to manage");
        inventory.setItem(42, networkButton);
    }
    
    private void openNetworkPage(Player player) {
        playerPages.put(player.getUniqueId(), "network");
        
        Inventory inventory = Bukkit.createInventory(null, 54, "§8§lNetwork Protection");
        
        ProxyIntegration proxyIntegration = plugin.getProxyIntegration();
        boolean isNetworkEnabled = plugin.isNetworkProtectionEnabled();
        
        ItemStack header = createGuiItem(Material.NETHER_STAR, "§d§lNetwork Protection", 
            "§7Manage cross-server protection",
            "§7Status: " + (isNetworkEnabled ? "§aENABLED" : "§cDISABLED"));
        inventory.setItem(4, header);
        
        if (!isNetworkEnabled) {
            ItemStack notEnabled = createGuiItem(Material.BARRIER, "§c§lNetwork Protection Disabled", 
                "§7Network protection is not enabled in config.yml",
                "§7Set network.enabled to true to enable");
            inventory.setItem(22, notEnabled);
        } else {
            String serverId = plugin.getConfig().getString("network.server-id", "Not set");
            String networkId = plugin.getConfig().getString("network.network-id", "default");
            
            ItemStack serverInfo = createGuiItem(Material.NAME_TAG, "§e§lServer Information", 
                "§7Server ID: §f" + serverId,
                "§7Network ID: §f" + networkId,
                "§7Role: " + (proxyIntegration.isMasterServer() ? "§6MASTER" : "§7NODE"));
            inventory.setItem(19, serverInfo);
            
            ItemStack syncStatus = createGuiItem(Material.CLOCK, "§e§lSync Status", 
                "§7Sync Blacklist: " + (plugin.getConfig().getBoolean("network.sync-blacklist", true) ? "§aYes" : "§cNo"),
                "§7Sync Whitelist: " + (plugin.getConfig().getBoolean("network.sync-whitelist", true) ? "§aYes" : "§cNo"),
                "§7Sync Attack Data: " + (plugin.getConfig().getBoolean("network.sync-attack-data", true) ? "§aYes" : "§cNo"));
            inventory.setItem(21, syncStatus);
            
            Set<String> servers = proxyIntegration.getNetworkServers();
            ItemStack serverList = createGuiItem(Material.MAP, "§e§lConnected Servers", 
                "§7Total servers: §f" + servers.size());
            inventory.setItem(23, serverList);
            
            if (proxyIntegration.isMasterServer()) {
                ItemStack masterStatus = createGuiItem(Material.GOLD_BLOCK, "§6§lMaster Server", 
                    "§7This server is the master server",
                    "§7All network synchronization runs through this server",
                    "",
                    "§eClick to force sync");
                inventory.setItem(25, masterStatus);
            } else {
                String masterId = proxyIntegration.getMasterServerId();
                ItemStack nodeStatus = createGuiItem(Material.IRON_BLOCK, "§7§lNode Server", 
                    "§7This server is a node server",
                    "§7Master server: §f" + (masterId.isEmpty() ? "None" : masterId),
                    "",
                    "§cClick to become master (use with caution!)");
                inventory.setItem(25, nodeStatus);
            }
            
            int slot = 28;
            for (String serverName : servers) {
                if (slot >= 45) break;
                
                boolean isMaster = serverName.equals(proxyIntegration.getMasterServerId());
                Material material = isMaster ? Material.BEACON : Material.END_PORTAL_FRAME;
                
                ItemStack serverItem = createGuiItem(material, 
                    (isMaster ? "§6§l" : "§f§l") + serverName, 
                    "§7Server ID: §f" + serverName,
                    "§7Role: " + (isMaster ? "§6MASTER" : "§7NODE"),
                    "",
                    "§eClick for details");
                
                inventory.setItem(slot++, serverItem);
            }
            
            if (servers.isEmpty()) {
                ItemStack noServers = createGuiItem(Material.BARRIER, "§c§lNo Servers Connected", 
                    "§7No other servers detected in the network",
                    "§7Proxy integration may not be working properly");
                inventory.setItem(31, noServers);
            }
        }
        
        ItemStack syncButton = createGuiItem(Material.COMPASS, "§a§lForce Sync", 
            "§7Force immediate data synchronization",
            "§7This will push all security data to other servers",
            "",
            "§eClick to force sync");
        inventory.setItem(47, syncButton);
        
        ItemStack settingsButton = createGuiItem(Material.COMMAND_BLOCK, "§e§lNetwork Settings", 
            "§7Configure network protection settings",
            "§7Adjust synchronization behavior",
            "",
            "§eClick to configure");
        inventory.setItem(51, settingsButton);
        
        ItemStack backButton = createGuiItem(Material.ARROW, "§c§lBack", 
            "§7Return to main dashboard");
        inventory.setItem(49, backButton);
        
        fillEmptySlots(inventory);
        player.openInventory(inventory);
        activeConsoles.put(player.getUniqueId(), inventory);
    }
    
    private void handleNetworkPageClick(Player player, int slot, ItemStack clickedItem) {
        ProxyIntegration proxyIntegration = plugin.getProxyIntegration();
        
        if (slot == 49) { // Back button
            Inventory dashboard = createMainDashboard(player);
            player.openInventory(dashboard);
            activeConsoles.put(player.getUniqueId(), dashboard);
            playerPages.put(player.getUniqueId(), "main");
            return;
        }
        
        if (!plugin.isNetworkProtectionEnabled()) {
            player.sendMessage("§c§lNetwork protection is not enabled!");
            player.sendMessage("§cEnable it in the config.yml file by setting network.enabled to true");
            return;
        }
        
        switch (slot) {
            case 25: // Master/Node status
                if (proxyIntegration.isMasterServer()) {
                    player.sendMessage("§e§lForcing data synchronization...");
                    Bukkit.getScheduler().runTaskAsynchronously(plugin, () -> {
                        proxyIntegration.loadConfig();
                    });
                } else {
                    player.closeInventory();
                    player.sendMessage("§c§lWARNING: §eYou are about to make this server the master server!");
                    player.sendMessage("§eThis will override the current master server.");
                    player.sendMessage("§eTo confirm, type: §6/nantiddos network master force");
                }
                break;
                
            case 47: // Force sync
                if (proxyIntegration.isMasterServer()) {
                    player.sendMessage("§a§lForcing network data synchronization...");
                    Bukkit.getScheduler().runTaskAsynchronously(plugin, () -> {
                        proxyIntegration.loadConfig();
                    });
                } else {
                    player.sendMessage("§c§lOnly the master server can force a synchronization!");
                    player.sendMessage("§cCurrent master: " + proxyIntegration.getMasterServerId());
                }
                break;
                
            case 51: // Settings
                player.closeInventory();
                player.performCommand("nantiddos network status");
                player.sendMessage("§eUse §6/nantiddos network §eto manage network settings");
                break;
        }
    }
    
    @EventHandler
    public void onInventoryClick(InventoryClickEvent event) {
        if (!(event.getWhoClicked() instanceof Player)) return;
        
        Player player = (Player) event.getWhoClicked();
        UUID playerId = player.getUniqueId();
        
        if (!activeConsoles.containsKey(playerId)) return;
        
        event.setCancelled(true);
        
        ItemStack clickedItem = event.getCurrentItem();
        if (clickedItem == null || clickedItem.getType() == Material.GRAY_STAINED_GLASS_PANE) return;
        
        String currentPage = playerPages.getOrDefault(playerId, "main");
        int slot = event.getRawSlot();
        
        if (slot > event.getView().getTopInventory().getSize()) return;
        
        player.playSound(player.getLocation(), Sound.BLOCK_NOTE_BLOCK_PLING, 0.5f, 1.2f);
        
        switch (currentPage) {
            case "main":
                handleMainDashboardClick(player, slot, clickedItem);
                break;
            case "analytics":
                handleAnalyticsPageClick(player, slot, clickedItem);
                break;
            case "reports":
                handleReportsPageClick(player, slot, clickedItem);
                break;
            case "attackTypes":
            case "threatMap":
                if (slot == 49) { // Back button
                    openAnalyticsPage(player, 0);
                }
                break;
            case "reportView":
                if (slot == 49) { // Back button
                    openReportsPage(player, 0);
                }
                break;
            case "network":
                handleNetworkPageClick(player, slot, clickedItem);
                break;
        }
    }
    
    private void handleMainDashboardClick(Player player, int slot, ItemStack clickedItem) {
        switch (slot) {
            case 19: // Connections Monitor
                openConnectionsPage(player);
                break;
            case 21: // Whitelist
                openWhitelistPage(player);
                break;
            case 23: // Blacklist
                openBlacklistPage(player);
                break;
            case 25: // Packets
                openPacketsPage(player);
                break;
            case 40: // Analytics
                openAnalyticsPage(player, 0);
                break;
            case 42: // Network Protection
                openNetworkPage(player);
                break;
            case 45: // Kick suspicious
                kickSuspiciousPlayers(player);
                break;
            case 53: // Exit
                player.closeInventory();
                playerPages.remove(player.getUniqueId());
                activeConsoles.remove(player.getUniqueId());
                break;
        }
    }
    
    private void handleAnalyticsPageClick(Player player, int slot, ItemStack clickedItem) {
        switch (slot) {
            case 10: // Threat Overview
                openThreatMapPage(player);
                break;
            case 12: // Attack Statistics
                openAttackTypesPage(player);
                break;
            case 29: // Daily Report
                player.performCommand("nantiddos analytics report daily");
                player.closeInventory();
                break;
            case 31: // Weekly Report
                player.performCommand("nantiddos analytics report weekly");
                player.closeInventory();
                break;
            case 33: // Reports Archive
                openReportsPage(player, 0);
                break;
            case 40: // Generate Custom Report
                player.closeInventory();
                player.sendMessage("§e§l[NantiDDoS] §fTo generate a custom report, use the command:");
                player.sendMessage("§e/nantiddos analytics report custom <start-date> <end-date>");
                player.sendMessage("§eDates should be in yyyy-MM-dd format");
                break;
            case 49: // Back button
                Inventory dashboard = createMainDashboard(player);
                player.openInventory(dashboard);
                activeConsoles.put(player.getUniqueId(), dashboard);
                playerPages.put(player.getUniqueId(), "main");
                break;
        }
    }
    
    private void handleReportsPageClick(Player player, int slot, ItemStack clickedItem) {
        if (slot == 49) { // Back button
            openAnalyticsPage(player, 0);
            return;
        }
        
        if (slot == 45 && clickedItem.getType() == Material.ARROW) {
            // Previous page
            int currentPage = 0;
            String pageText = ChatColor.stripColor(clickedItem.getItemMeta().getLore().get(0));
            try {
                currentPage = Integer.parseInt(pageText.replace("Go to page ", "")) - 1;
            } catch (NumberFormatException | IndexOutOfBoundsException e) {
                currentPage = 0;
            }
            openReportsPage(player, Math.max(0, currentPage));
            return;
        }
        
        if (slot == 53 && clickedItem.getType() == Material.ARROW) {
            // Next page
            int currentPage = 0;
            String pageText = ChatColor.stripColor(clickedItem.getItemMeta().getLore().get(0));
            try {
                currentPage = Integer.parseInt(pageText.replace("Go to page ", "")) - 1;
            } catch (NumberFormatException | IndexOutOfBoundsException e) {
                currentPage = 0;
            }
            openReportsPage(player, currentPage);
            return;
        }
        
        // Check if clicked on a report
        if (slot >= 9 && slot < 45 && clickedItem != null && 
            (clickedItem.getType() == Material.PAPER || 
             clickedItem.getType() == Material.BOOK || 
             clickedItem.getType() == Material.WRITABLE_BOOK || 
             clickedItem.getType() == Material.MAP)) {
            
            List<Map<String, String>> reports = securityMetrics.getReportHistory();
            int currentPage = 0;
            int reportIndex = slot - 9 + (currentPage * 36);
            
            if (reportIndex < reports.size()) {
                Map<String, String> report = reports.get(reportIndex);
                String path = report.getOrDefault("path", null);
                
                if (path != null) {
                    openReportViewPage(player, path);
                }
            }
        }
    }
    
    @EventHandler
    public void onPlayerQuit(PlayerQuitEvent event) {
        UUID playerId = event.getPlayer().getUniqueId();
        playerPages.remove(playerId);
        activeConsoles.remove(playerId);
        ipInspections.remove(playerId);
        analyticsPages.remove(playerId);
        reportViewers.remove(playerId);
    }
    
    @EventHandler
    public void onPlayerChat(AsyncPlayerChatEvent event) {
        Player player = event.getPlayer();
        UUID playerId = player.getUniqueId();
        
        // Existing code for handling chat input for whitelist/blacklist prompts
    }
    
    private void openConnectionsPage(Player player) {
        playerPages.put(player.getUniqueId(), "connections");
        
        Inventory inventory = Bukkit.createInventory(null, 54, "§8§lConnection Monitor");
        
        ItemStack header = createGuiItem(Material.COMPASS, "§e§lActive Connections", 
            "§7View and manage active connections",
            "§7Generated: §f" + dateFormat.format(new Date()));
        inventory.setItem(4, header);
        
        Map<String, ConnectionTracker.ConnectionData> connectionMap = connectionTracker.getConnectionMap();
        Map<String, Integer> botScores = connectionTracker.getBotScores();
        
        if (connectionMap.isEmpty()) {
            ItemStack noData = createGuiItem(Material.BARRIER, "§e§lNo Active Connections", 
                "§7No connection data available");
            inventory.setItem(22, noData);
        } else {
            List<Map.Entry<String, ConnectionTracker.ConnectionData>> sortedConnections = 
                new ArrayList<>(connectionMap.entrySet());
            
            sortedConnections.sort((e1, e2) -> {
                int score1 = botScores.getOrDefault(e1.getKey(), 0);
                int score2 = botScores.getOrDefault(e2.getKey(), 0);
                return score2 - score1;
            });
            
            int slot = 9;
            for (Map.Entry<String, ConnectionTracker.ConnectionData> entry : sortedConnections) {
                if (slot >= 45) break;
                
                String ip = entry.getKey();
                ConnectionTracker.ConnectionData data = entry.getValue();
                int botScore = botScores.getOrDefault(ip, 0);
                
                Material material;
                if (botScore >= 20) {
                    material = Material.RED_CONCRETE;
                } else if (botScore >= 10) {
                    material = Material.ORANGE_CONCRETE;
                } else if (botScore >= 5) {
                    material = Material.YELLOW_CONCRETE;
                } else {
                    material = Material.LIME_CONCRETE;
                }
                
                ItemStack ipItem = createGuiItem(material, "§f§l" + ip, 
                    "§7Bot Score: §f" + formatBotScoreColor(botScore),
                    "§7Connections: §f" + data.getConnectionCount(),
                    "§7First Seen: §f" + dateFormat.format(new Date(data.getFirstConnectionTime())),
                    "§7Last Seen: §f" + dateFormat.format(new Date(data.getLastConnectionTime())),
                    "",
                    "§eLeft-Click to inspect",
                    "§cRight-Click to blacklist");
                
                inventory.setItem(slot++, ipItem);
            }
            
            ItemStack botScoreInfo = createGuiItem(Material.BOOK, "§e§lBot Score Legend", 
                "§a0-4: §7Low probability - Normal connection",
                "§e5-9: §7Moderate probability - Suspicious connection",
                "§610-19: §7High probability - Likely bot",
                "§c20+: §7Very high probability - Almost certain bot");
            inventory.setItem(48, botScoreInfo);
        }
        
        ItemStack refreshButton = createGuiItem(Material.CLOCK, "§a§lRefresh Data", 
            "§7Update connection information");
        inventory.setItem(47, refreshButton);
        
        ItemStack blacklistAllButton = createGuiItem(Material.TNT, "§c§lBlacklist Suspicious", 
            "§7Blacklist all connections with high bot scores",
            "§7This will add IPs with bot score > 15 to blacklist",
            "",
            "§c§lWARNING: Use with caution!");
        inventory.setItem(51, blacklistAllButton);
        
        ItemStack backButton = createGuiItem(Material.ARROW, "§c§lBack", 
            "§7Return to main dashboard");
        inventory.setItem(49, backButton);
        
        fillEmptySlots(inventory);
        player.openInventory(inventory);
        activeConsoles.put(player.getUniqueId(), inventory);
    }
    
    private void openWhitelistPage(Player player) {
        playerPages.put(player.getUniqueId(), "whitelist");
        
        Inventory inventory = Bukkit.createInventory(null, 54, "§8§lWhitelist Management");
        
        ItemStack header = createGuiItem(Material.PAPER, "§a§lWhitelist Management", 
            "§7View and manage whitelisted IPs",
            "§7Whitelisted IPs are exempt from all protection measures");
        inventory.setItem(4, header);
        
        Set<String> whitelistedIps = ipManager.getWhitelistedIps();
        List<String> sortedIps = new ArrayList<>(whitelistedIps);
        Collections.sort(sortedIps);
        
        if (sortedIps.isEmpty()) {
            ItemStack noData = createGuiItem(Material.BARRIER, "§e§lNo Whitelisted IPs", 
                "§7The whitelist is empty",
                "§7Add IPs to exempt them from protection measures");
            inventory.setItem(22, noData);
        } else {
            int slot = 9;
            for (String ip : sortedIps) {
                if (slot >= 45) break;
                
                ItemStack ipItem = createGuiItem(Material.PAPER, "§a§l" + ip, 
                    "§7Status: §aWhitelisted",
                    "§7This IP is exempt from all protection measures",
                    "",
                    "§cClick to remove from whitelist");
                
                inventory.setItem(slot++, ipItem);
            }
        }
        
        ItemStack addButton = createGuiItem(Material.EMERALD, "§a§lAdd IP to Whitelist", 
            "§7Add a new IP address to the whitelist",
            "§7You will be prompted to enter the IP in chat");
        inventory.setItem(47, addButton);
        
        ItemStack networksButton = createGuiItem(Material.MAP, "§a§lManage Networks", 
            "§7View and manage whitelisted CIDR networks",
            "§7Number of networks: §f" + ipManager.getWhitelistedNetworks().size());
        inventory.setItem(51, networksButton);
        
        ItemStack backButton = createGuiItem(Material.ARROW, "§c§lBack", 
            "§7Return to main dashboard");
        inventory.setItem(49, backButton);
        
        fillEmptySlots(inventory);
        player.openInventory(inventory);
        activeConsoles.put(player.getUniqueId(), inventory);
    }
    
    private void openBlacklistPage(Player player) {
        playerPages.put(player.getUniqueId(), "blacklist");
        
        Inventory inventory = Bukkit.createInventory(null, 54, "§8§lBlacklist Management");
        
        ItemStack header = createGuiItem(Material.BARRIER, "§c§lBlacklist Management", 
            "§7View and manage blacklisted IPs",
            "§7Blacklisted IPs cannot connect to the server");
        inventory.setItem(4, header);
        
        Set<String> blacklistedIps = ipManager.getBlacklistedIps();
        List<String> sortedIps = new ArrayList<>(blacklistedIps);
        Collections.sort(sortedIps);
        
        if (sortedIps.isEmpty()) {
            ItemStack noData = createGuiItem(Material.BARRIER, "§e§lNo Blacklisted IPs", 
                "§7The blacklist is empty");
            inventory.setItem(22, noData);
        } else {
            int slot = 9;
            int page = 0;
            int startIndex = page * 36;
            int endIndex = Math.min(startIndex + 36, sortedIps.size());
            
            for (int i = startIndex; i < endIndex; i++) {
                String ip = sortedIps.get(i);
                
                ItemStack ipItem = createGuiItem(Material.BARRIER, "§c§l" + ip, 
                    "§7Status: §cBlacklisted",
                    "§7This IP cannot connect to the server",
                    "",
                    "§eClick to remove from blacklist");
                
                inventory.setItem(slot++, ipItem);
            }
            
            if (sortedIps.size() > 36) {
                ItemStack nextPage = createGuiItem(Material.ARROW, "§e§lNext Page", 
                    "§7View more blacklisted IPs");
                inventory.setItem(53, nextPage);
            }
        }
        
        ItemStack addButton = createGuiItem(Material.REDSTONE, "§c§lAdd IP to Blacklist", 
            "§7Add a new IP address to the blacklist",
            "§7You will be prompted to enter the IP in chat");
        inventory.setItem(47, addButton);
        
        ItemStack networksButton = createGuiItem(Material.MAP, "§c§lManage Networks", 
            "§7View and manage blacklisted CIDR networks",
            "§7Number of networks: §f" + ipManager.getBlacklistedNetworks().size());
        inventory.setItem(51, networksButton);
        
        ItemStack backButton = createGuiItem(Material.ARROW, "§c§lBack", 
            "§7Return to main dashboard");
        inventory.setItem(49, backButton);
        
        fillEmptySlots(inventory);
        player.openInventory(inventory);
        activeConsoles.put(player.getUniqueId(), inventory);
    }
    
    private void openPacketsPage(Player player) {
        playerPages.put(player.getUniqueId(), "packets");
        
        Inventory inventory = Bukkit.createInventory(null, 54, "§8§lPacket Analysis");
        
        ItemStack header = createGuiItem(Material.REPEATER, "§b§lPacket Monitoring", 
            "§7View packet monitoring statistics",
            "§7Status: " + (packetMonitor.isPacketMonitoringFullyAvailable() ? "§aFull" : "§eBasic"));
        inventory.setItem(4, header);
        
        if (!packetMonitor.isPacketMonitoringFullyAvailable()) {
            ItemStack warningItem = createGuiItem(Material.ORANGE_CONCRETE, "§e§lLimited Functionality", 
                "§7ProtocolLib is not installed",
                "§7Install ProtocolLib for full packet analysis");
            inventory.setItem(13, warningItem);
        }
        
        ItemStack statsItem = createGuiItem(Material.BOOK, "§e§lStatistics", 
            "§7Active monitoring sessions: §f" + packetMonitor.getActivePacketMonitoringSessions(),
            "§7Suspicious packet sources: §c" + packetMonitor.getSuspiciousPacketSources());
        inventory.setItem(19, statsItem);
        
        List<Player> onlinePlayers = new ArrayList<>(Bukkit.getOnlinePlayers());
        onlinePlayers.sort((p1, p2) -> p1.getName().compareTo(p2.getName()));
        
        if (onlinePlayers.isEmpty()) {
            ItemStack noPlayers = createGuiItem(Material.BARRIER, "§e§lNo Players Online", 
                "§7No players available for packet analysis");
            inventory.setItem(31, noPlayers);
        } else {
            int slot = 28;
            for (Player p : onlinePlayers) {
                if (slot >= 45 || slot % 9 >= 7) continue;
                
                UUID playerId = p.getUniqueId();
                Material playerHead = Material.PLAYER_HEAD;
                
                ItemStack playerItem = createGuiItem(playerHead, "§e§l" + p.getName(), 
                    "§7Click to view packet statistics",
                    "§7and manage this player's packets");
                
                inventory.setItem(slot++, playerItem);
            }
        }
        
        ItemStack settingsButton = createGuiItem(Material.COMPARATOR, "§e§lPacket Settings", 
            "§7Adjust packet monitoring thresholds",
            "§7and other packet analysis settings");
        inventory.setItem(47, settingsButton);
        
        ItemStack resetButton = createGuiItem(Material.REDSTONE_TORCH, "§c§lReset Statistics", 
            "§7Clear all packet monitoring data",
            "§7This will reset all packet counters");
        inventory.setItem(51, resetButton);
        
        ItemStack backButton = createGuiItem(Material.ARROW, "§c§lBack", 
            "§7Return to main dashboard");
        inventory.setItem(49, backButton);
        
        fillEmptySlots(inventory);
        player.openInventory(inventory);
        activeConsoles.put(player.getUniqueId(), inventory);
    }
    
    private void kickSuspiciousPlayers(Player player) {
        int kickCount = 0;
        List<String> kickedPlayers = new ArrayList<>();
        
        for (Player onlinePlayer : Bukkit.getOnlinePlayers()) {
            if (onlinePlayer.equals(player) || onlinePlayer.hasPermission("nantiddos.admin")) continue;
            
            if (onlinePlayer.getAddress() != null) {
                String ip = onlinePlayer.getAddress().getAddress().getHostAddress();
                Map<String, AttackDetector.AttackData> attackDataMap = attackDetector.getAttackDataMap();
                
                if (attackDataMap.containsKey(ip)) {
                    AttackDetector.AttackData data = attackDataMap.get(ip);
                    
                    if (data.getCurrentRiskScore() >= 75 || data.getAlertLevel().getLevel() >= AlertLevel.HIGH.getLevel()) {
                        kickedPlayers.add(onlinePlayer.getName());
                        onlinePlayer.kickPlayer("§c§lYou have been kicked for suspicious activity");
                        kickCount++;
                    }
                }
                
                Map<String, Integer> botScores = connectionTracker.getBotScores();
                if (botScores.containsKey(ip) && botScores.get(ip) >= 15) {
                    kickedPlayers.add(onlinePlayer.getName());
                    onlinePlayer.kickPlayer("§c§lYou have been kicked for suspicious connection patterns");
                    kickCount++;
                }
            }
        }
        
        if (kickCount > 0) {
            player.sendMessage("§e§l[NantiDDoS] §cKicked " + kickCount + " suspicious players:");
            for (String name : kickedPlayers) {
                player.sendMessage("§c- " + name);
            }
        } else {
            player.sendMessage("§e§l[NantiDDoS] §aNo suspicious players found to kick.");
        }
        
        player.playSound(player.getLocation(), Sound.BLOCK_ANVIL_LAND, 0.5f, 1.0f);
        player.closeInventory();
    }
}