package id.nantiddos.dashboard;

import id.nantiddos.Nantiddos;
import id.nantiddos.analytics.SecurityMetrics;
import id.nantiddos.protection.AttackDetector;
import id.nantiddos.protection.AttackDetector.AlertLevel;
import id.nantiddos.protection.AttackDetector.AttackType;
import id.nantiddos.protection.ConnectionTracker;
import id.nantiddos.protection.IPManager;
import id.nantiddos.protection.PacketMonitor;

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
    }
    
    private void openAnalyticsPage(Player player, int page) {
        playerPages.put(player.getUniqueId(), "analytics");
        analyticsPages.put(player.getUniqueId(), page);
        
        Inventory inventory = Bukkit.createInventory(null, 54, "§8§lSecurity Analytics Dashboard");
        
        ItemStack header = createGuiItem(Material.KNOWLEDGE_BOOK, "§d§lSecurity Analytics", 
            "§7View detailed security statistics and reports",
            "§7Generated: §f" + dateFormat.format(new Date()));
        inventory.setItem(4, header);
        
        Map<String, Object> data = securityMetrics.generateAnalyticsData();
        
        int currentThreatLevel = (int) data.getOrDefault("currentThreatLevel", 0);
        AlertLevel alertLevel = attackDetector.getSystemAlertLevel();
        String alertColor = alertLevel.getColor();
        
        Material trendMaterial = Material.GOLDEN_SWORD;
        String trendDirection = "§eStable";
        
        if (data.containsKey("threatTrend")) {
            int trend = (int) data.get("threatTrend");
            if (trend > 10) {
                trendMaterial = Material.DIAMOND_SWORD;
                trendDirection = "§c▲ Increasing";
            } else if (trend < -10) {
                trendMaterial = Material.WOODEN_SWORD;
                trendDirection = "§a▼ Decreasing";
            }
        }
        
        ItemStack threatOverview = createGuiItem(trendMaterial, "§e§lThreat Overview", 
            "§7Current Threat Level: " + alertColor + alertLevel.name(),
            "§7Threat Score: §f" + currentThreatLevel + "/100",
            "§7Trend: " + trendDirection,
            "§7Active Attack Sources: §c" + data.getOrDefault("activeAttackSources", 0),
            "",
            "§eClick for detailed threat analysis");
        inventory.setItem(10, threatOverview);
        
        ItemStack attackStats = createGuiItem(Material.FIRE_CHARGE, "§c§lAttack Statistics", 
            "§7Total Attacks (7d): §c" + data.getOrDefault("totalAttacks", 0),
            "§7High Severity Attacks: §c" + data.getOrDefault("highSeverityAttacks", 0),
            "§7Most Common Attack: §e" + getMostCommonAttackType(data),
            "",
            "§eClick to view attack types");
        inventory.setItem(12, attackStats);
        
        ItemStack connectionStats = createGuiItem(Material.COMPASS, "§b§lConnection Statistics", 
            "§7Total Connections (7d): §f" + data.getOrDefault("totalConnections", 0),
            "§7Max Connections/sec: §f" + data.getOrDefault("maxConnections", 0),
            "§7Average Connections/sec: §f" + getFormattedAverage(data, "avgConnections"),
            "§7Suspicious Connections: §c" + connectionTracker.getSuspiciousConnectionsCount(),
            "",
            "§eClick for connection history chart");
        inventory.setItem(14, connectionStats);
        
        ItemStack ipStats = createGuiItem(Material.MAP, "§a§lGeographic Analysis", 
            "§7Total Unique IPs: §f" + connectionTracker.getConnectionsCount(),
            "§7Blacklisted IPs: §c" + ipManager.getBlacklistedIps().size(),
            "§7Whitelisted IPs: §a" + ipManager.getWhitelistedIps().size(),
            "",
            "§eClick to view IP threat map");
        inventory.setItem(16, ipStats);
        
        ItemStack dailyReport = createGuiItem(Material.PAPER, "§e§lDaily Report", 
            "§7View today's security summary",
            "§7Contains hourly statistics, attack patterns,",
            "§7and security recommendations",
            "",
            "§eClick to view today's report");
        inventory.setItem(29, dailyReport);
        
        ItemStack weeklyReport = createGuiItem(Material.BOOK, "§6§lWeekly Report", 
            "§7View this week's security trends",
            "§7Includes daily summaries, attack patterns,",
            "§7and long-term security analysis",
            "",
            "§eClick to view weekly report");
        inventory.setItem(31, weeklyReport);
        
        ItemStack reportsArchive = createGuiItem(Material.BOOKSHELF, "§d§lReports Archive", 
            "§7Browse all security reports",
            "§7Access historical security data",
            "§7and custom report generation",
            "",
            "§eClick to browse reports");
        inventory.setItem(33, reportsArchive);
        
        ItemStack generateReport = createGuiItem(Material.WRITABLE_BOOK, "§b§lGenerate Custom Report", 
            "§7Create a custom security report",
            "§7Specify date range and report type",
            "",
            "§eClick to generate report");
        inventory.setItem(40, generateReport);
        
        ItemStack backButton = createGuiItem(Material.ARROW, "§c§lBack", 
            "§7Return to main dashboard");
        inventory.setItem(49, backButton);
        
        fillEmptySlots(inventory);
        player.openInventory(inventory);
        activeConsoles.put(player.getUniqueId(), inventory);
    }
    
    private void openReportsPage(Player player, int page) {
        playerPages.put(player.getUniqueId(), "reports");
        
        Inventory inventory = Bukkit.createInventory(null, 54, "§8§lSecurity Reports Archive");
        
        ItemStack header = createGuiItem(Material.BOOKSHELF, "§d§lSecurity Reports Archive", 
            "§7Browse and access all security reports",
            "§7Page: §f" + (page + 1));
        inventory.setItem(4, header);
        
        List<Map<String, String>> reports = securityMetrics.getReportHistory();
        
        if (reports.isEmpty()) {
            ItemStack noReports = createGuiItem(Material.BARRIER, "§c§lNo Reports Available", 
                "§7No security reports have been generated yet",
                "§7Reports are generated automatically or manually");
            inventory.setItem(22, noReports);
        } else {
            int startIndex = page * 36;
            int endIndex = Math.min(startIndex + 36, reports.size());
            int slot = 9;
            
            for (int i = startIndex; i < endIndex; i++) {
                Map<String, String> report = reports.get(i);
                
                String fileName = report.getOrDefault("fileName", report.getOrDefault("path", "Unknown"));
                if (fileName.contains("\\")) {
                    fileName = fileName.substring(fileName.lastIndexOf('\\') + 1);
                }
                String date = report.getOrDefault("date", report.getOrDefault("timestamp", "Unknown"));
                String size = report.getOrDefault("size", "Unknown");
                String filePath = report.getOrDefault("path", "");
                
                Material material;
                if (fileName.contains("daily")) {
                    material = Material.PAPER;
                } else if (fileName.contains("weekly")) {
                    material = Material.BOOK;
                } else if (fileName.contains("custom")) {
                    material = Material.WRITABLE_BOOK;
                } else {
                    material = Material.MAP;
                }
                
                ItemStack reportItem = createGuiItem(material, "§e§l" + fileName, 
                    "§7Date: §f" + date,
                    "§7Size: §f" + size,
                    "",
                    "§eClick to view report details");
                
                inventory.setItem(slot++, reportItem);
                
                if (slot >= 45) break;
            }
            
            if (page > 0) {
                ItemStack prevPage = createGuiItem(Material.ARROW, "§e§lPrevious Page", 
                    "§7Go to page " + page);
                inventory.setItem(45, prevPage);
            }
            
            if (endIndex < reports.size()) {
                ItemStack nextPage = createGuiItem(Material.ARROW, "§e§lNext Page", 
                    "§7Go to page " + (page + 2));
                inventory.setItem(53, nextPage);
            }
        }
        
        ItemStack backButton = createGuiItem(Material.BARRIER, "§c§lBack", 
            "§7Return to analytics dashboard");
        inventory.setItem(49, backButton);
        
        fillEmptySlots(inventory);
        player.openInventory(inventory);
        activeConsoles.put(player.getUniqueId(), inventory);
    }
    
    private void openAttackTypesPage(Player player) {
        playerPages.put(player.getUniqueId(), "attackTypes");
        
        Inventory inventory = Bukkit.createInventory(null, 54, "§8§lAttack Type Analysis");
        
        ItemStack header = createGuiItem(Material.FIRE_CHARGE, "§c§lAttack Type Analysis", 
            "§7View detailed statistics by attack type",
            "§7Generated: §f" + dateFormat.format(new Date()));
        inventory.setItem(4, header);
        
        Map<String, Object> data = securityMetrics.generateAnalyticsData();
        
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> attackTypes = (List<Map<String, Object>>) data.get("attackTypes");
        
        if (attackTypes != null && !attackTypes.isEmpty()) {
            int slot = 10;
            for (Map<String, Object> attackType : attackTypes) {
                String type = (String) attackType.get("type");
                int count = ((Number) attackType.get("count")).intValue();
                
                Material material;
                String color;
                
                if (type.contains("CONNECTION_FLOOD")) {
                    material = Material.BLUE_CONCRETE;
                    color = "§9";
                } else if (type.contains("LOGIN_FLOOD")) {
                    material = Material.CYAN_CONCRETE;
                    color = "§3";
                } else if (type.contains("PING_FLOOD")) {
                    material = Material.LIGHT_BLUE_CONCRETE;
                    color = "§b";
                } else if (type.contains("PACKET_FLOOD")) {
                    material = Material.RED_CONCRETE;
                    color = "§c";
                } else if (type.contains("BOT_NETWORK")) {
                    material = Material.ORANGE_CONCRETE;
                    color = "§6";
                } else if (type.contains("DISTRIBUTED")) {
                    material = Material.PURPLE_CONCRETE;
                    color = "§5";
                } else {
                    material = Material.GRAY_CONCRETE;
                    color = "§7";
                }
                
                ItemStack attackItem = createGuiItem(material, color + "§l" + type, 
                    "§7Total Occurrences: §c" + count,
                    "§7Severity: §e" + getSeverityForAttackType(type),
                    "",
                    "§eClick to view attack details");
                
                inventory.setItem(slot++, attackItem);
                
                if ((slot - 10) % 9 == 7) {
                    slot += 3;
                }
                
                if (slot >= 44) break;
            }
        } else {
            ItemStack noAttacks = createGuiItem(Material.BARRIER, "§a§lNo Attacks Detected", 
                "§7No attack data available",
                "§7Your server appears to be secure");
            inventory.setItem(22, noAttacks);
        }
        
        ItemStack backButton = createGuiItem(Material.ARROW, "§c§lBack", 
            "§7Return to analytics dashboard");
        inventory.setItem(49, backButton);
        
        fillEmptySlots(inventory);
        player.openInventory(inventory);
        activeConsoles.put(player.getUniqueId(), inventory);
    }
    
    private void openThreatMapPage(Player player) {
        playerPages.put(player.getUniqueId(), "threatMap");
        
        Inventory inventory = Bukkit.createInventory(null, 54, "§8§lIP Threat Map");
        
        ItemStack header = createGuiItem(Material.MAP, "§a§lIP Threat Map", 
            "§7Visual representation of threat sources",
            "§7Generated: §f" + dateFormat.format(new Date()));
        inventory.setItem(4, header);
        
        Map<String, AttackDetector.AttackData> attackDataMap = attackDetector.getAttackDataMap();
        Map<String, ConnectionTracker.ConnectionData> connectionMap = connectionTracker.getConnectionMap();
        Map<String, Integer> botScores = connectionTracker.getBotScores();
        
        if (attackDataMap.isEmpty() && connectionMap.isEmpty()) {
            ItemStack noData = createGuiItem(Material.BARRIER, "§a§lNo Threat Data Available", 
                "§7No threat sources identified");
            inventory.setItem(22, noData);
        } else {
            int slot = 9;
            
            List<Map.Entry<String, AttackDetector.AttackData>> sortedAttacks = new ArrayList<>(attackDataMap.entrySet());
            sortedAttacks.sort((e1, e2) -> e2.getValue().getCurrentRiskScore() - e1.getValue().getCurrentRiskScore());
            
            for (Map.Entry<String, AttackDetector.AttackData> entry : sortedAttacks) {
                if (slot >= 45) break;
                
                String ip = entry.getKey();
                AttackDetector.AttackData data = entry.getValue();
                int threatScore = data.getCurrentRiskScore();
                AlertLevel alertLevel = data.getAlertLevel();
                AttackType primaryType = data.getPrimaryAttackType();
                
                Material material;
                switch (alertLevel) {
                    case CRITICAL: material = Material.RED_CONCRETE; break;
                    case HIGH: material = Material.ORANGE_CONCRETE; break;
                    case MEDIUM: material = Material.YELLOW_CONCRETE; break;
                    case LOW: material = Material.LIME_CONCRETE; break;
                    default: material = Material.GREEN_CONCRETE; break;
                }
                
                ItemStack ipItem = createGuiItem(material, alertLevel.getColor() + "§l" + ip, 
                    "§7Threat Score: §f" + threatScore + "/100",
                    "§7Alert Level: " + alertLevel.getColor() + alertLevel.name(),
                    "§7Attack Type: §f" + primaryType.getName(),
                    "§7Bot Score: §f" + botScores.getOrDefault(ip, 0),
                    "",
                    "§eClick to inspect this IP");
                
                inventory.setItem(slot++, ipItem);
            }
            
            if (slot == 9) {
                ItemStack noThreats = createGuiItem(Material.GREEN_CONCRETE, "§a§lNo Active Threats", 
                    "§7No active threats detected",
                    "§7Your server appears to be secure");
                inventory.setItem(22, noThreats);
            }
        }
        
        ItemStack legend = createGuiItem(Material.BOOK, "§e§lThreat Level Legend", 
            "§a■ §7NORMAL - No significant threat",
            "§e■ §7LOW - Minor suspicious activity",
            "§6■ §7MEDIUM - Suspicious traffic patterns",
            "§c■ §7HIGH - Likely attack in progress",
            "§4■ §7CRITICAL - Active attack confirmed");
        inventory.setItem(48, legend);
        
        ItemStack backButton = createGuiItem(Material.ARROW, "§c§lBack", 
            "§7Return to analytics dashboard");
        inventory.setItem(49, backButton);
        
        fillEmptySlots(inventory);
        player.openInventory(inventory);
        activeConsoles.put(player.getUniqueId(), inventory);
    }
    
    private void openReportViewPage(Player player, String reportPath) {
        playerPages.put(player.getUniqueId(), "reportView");
        reportViewers.put(player.getUniqueId(), reportPath);
        
        String fileName = reportPath;
        if (fileName.contains("\\")) {
            fileName = fileName.substring(fileName.lastIndexOf('\\') + 1);
        }
        
        Inventory inventory = Bukkit.createInventory(null, 54, "§8§lReport: " + fileName);
        
        ItemStack header = createGuiItem(Material.PAPER, "§e§l" + fileName, 
            "§7Report file: §f" + reportPath);
        inventory.setItem(4, header);
        
        // Simplified report content visualization
        // In real implementation, this would parse and display the actual report content
        
        LocalDate reportDate = LocalDate.now();
        if (fileName.contains("daily")) {
            try {
                String dateStr = fileName.replace("daily_report_", "").replace(".csv", "").replace(".json", "");
                reportDate = LocalDate.parse(dateStr);
            } catch (Exception e) {
                // Use current date if parsing fails
            }
            
            ItemStack summaryItem = createGuiItem(Material.BOOK, "§e§lDaily Summary: " + reportDate.format(dateOnlyFormat), 
                "§7View summary statistics for this day");
            inventory.setItem(19, summaryItem);
            
            ItemStack hourlyItem = createGuiItem(Material.CLOCK, "§e§lHourly Breakdown", 
                "§7View hourly activity patterns for this day");
            inventory.setItem(21, hourlyItem);
            
            ItemStack attacksItem = createGuiItem(Material.FIRE_CHARGE, "§c§lAttack Summary", 
                "§7View attack patterns detected on this day");
            inventory.setItem(23, attacksItem);
            
            ItemStack sourcesItem = createGuiItem(Material.MAP, "§6§lAttack Sources", 
                "§7View geographical distribution of attacks");
            inventory.setItem(25, sourcesItem);
            
        } else if (fileName.contains("weekly")) {
            try {
                String dateRange = fileName.replace("weekly_report_", "").replace(".csv", "").replace(".json", "");
                String startDate = dateRange.split("_to_")[0];
                reportDate = LocalDate.parse(startDate);
            } catch (Exception e) {
                // Use current date if parsing fails
            }
            
            ItemStack summaryItem = createGuiItem(Material.BOOK, "§6§lWeekly Summary: " + reportDate.format(dateOnlyFormat), 
                "§7View summary statistics for this week");
            inventory.setItem(19, summaryItem);
            
            ItemStack dailyItem = createGuiItem(Material.CLOCK, "§6§lDaily Breakdown", 
                "§7View day-by-day activity patterns");
            inventory.setItem(21, dailyItem);
            
            ItemStack trendsItem = createGuiItem(Material.GOLDEN_SWORD, "§6§lThreat Trends", 
                "§7View threat level trends over the week");
            inventory.setItem(23, trendsItem);
            
            ItemStack attackTypesItem = createGuiItem(Material.FIRE_CHARGE, "§c§lAttack Types", 
                "§7View breakdown of attack types for the week");
            inventory.setItem(25, attackTypesItem);
        }
        
        ItemStack exportCsvButton = createGuiItem(Material.MAP, "§a§lExport as CSV", 
            "§7Export this report data as CSV file");
        inventory.setItem(38, exportCsvButton);
        
        ItemStack exportJsonButton = createGuiItem(Material.FILLED_MAP, "§b§lExport as JSON", 
            "§7Export this report data as JSON file");
        inventory.setItem(40, exportJsonButton);
        
        ItemStack openFileButton = createGuiItem(Material.BOOKSHELF, "§d§lOpen File Location", 
            "§7Open the report file location",
            "§7Path: §f" + reportPath);
        inventory.setItem(42, openFileButton);
        
        ItemStack backButton = createGuiItem(Material.ARROW, "§c§lBack", 
            "§7Return to reports page");
        inventory.setItem(49, backButton);
        
        fillEmptySlots(inventory);
        player.openInventory(inventory);
        activeConsoles.put(player.getUniqueId(), inventory);
    }
    
    private String getMostCommonAttackType(Map<String, Object> data) {
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> attackTypes = (List<Map<String, Object>>) data.get("attackTypes");
        
        if (attackTypes != null && !attackTypes.isEmpty()) {
            Map<String, Object> mostCommon = attackTypes.get(0);
            return (String) mostCommon.get("type");
        }
        
        return "None";
    }
    
    private String getFormattedAverage(Map<String, Object> data, String key) {
        if (data.containsKey(key)) {
            Object value = data.get(key);
            if (value instanceof Number) {
                return String.format("%.1f", ((Number) value).doubleValue());
            }
            return value.toString();
        }
        return "0";
    }
    
    private String getSeverityForAttackType(String attackType) {
        if (attackType.contains("DISTRIBUTED")) return "Critical";
        if (attackType.contains("BOT_NETWORK")) return "High";
        if (attackType.contains("PACKET_FLOOD")) return "High";
        if (attackType.contains("LOGIN_FLOOD")) return "Medium";
        if (attackType.contains("CONNECTION_FLOOD")) return "Medium";
        if (attackType.contains("PING_FLOOD")) return "Low";
        return "Unknown";
    }
    
    private String formatBotScoreColor(int score) {
        if (score >= 20) return "§c" + score;
        if (score >= 10) return "§e" + score;
        return "§a" + score;
    }
    
    private void fillEmptySlots(Inventory inventory) {
        ItemStack filler = new ItemStack(Material.GRAY_STAINED_GLASS_PANE);
        ItemMeta meta = filler.getItemMeta();
        meta.setDisplayName(" ");
        filler.setItemMeta(meta);
        
        for (int i = 0; i < inventory.getSize(); i++) {
            if (inventory.getItem(i) == null) {
                inventory.setItem(i, filler);
            }
        }
    }
    
    private ItemStack createGuiItem(Material material, String name, String... lore) {
        ItemStack item = new ItemStack(material);
        ItemMeta meta = item.getItemMeta();
        meta.setDisplayName(name);
        
        if (lore.length > 0) {
            meta.setLore(Arrays.asList(lore));
        }
        
        item.setItemMeta(meta);
        return item;
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