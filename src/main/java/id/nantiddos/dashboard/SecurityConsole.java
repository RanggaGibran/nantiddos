package id.nantiddos.dashboard;

import id.nantiddos.Nantiddos;
import id.nantiddos.protection.ConnectionTracker;
import id.nantiddos.protection.IPManager;
import id.nantiddos.protection.PacketMonitor;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.logging.Logger;
import java.util.stream.Collectors;

import org.bukkit.Bukkit;
import org.bukkit.ChatColor;
import org.bukkit.Material;
import org.bukkit.Sound;
import org.bukkit.enchantments.Enchantment;
import org.bukkit.entity.Player;
import org.bukkit.event.EventHandler;
import org.bukkit.event.Listener;
import org.bukkit.event.inventory.InventoryClickEvent;
import org.bukkit.event.inventory.InventoryCloseEvent;
import org.bukkit.inventory.Inventory;
import org.bukkit.inventory.ItemFlag;
import org.bukkit.inventory.ItemStack;
import org.bukkit.inventory.meta.ItemMeta;
import org.bukkit.scheduler.BukkitTask;

public class SecurityConsole implements Listener {
    private final Nantiddos plugin;
    private final Logger logger;
    private final ConnectionTracker connectionTracker;
    private final IPManager ipManager;
    private final PacketMonitor packetMonitor;
    
    private final Map<UUID, Inventory> activeConsoles = new HashMap<>();
    private final Map<UUID, String> playerPages = new HashMap<>();
    private final Map<UUID, String> ipInspections = new HashMap<>();
    private final SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
    
    private BukkitTask refreshTask;
    private boolean enabled = true;
    
    public SecurityConsole(Nantiddos plugin, ConnectionTracker connectionTracker, IPManager ipManager, PacketMonitor packetMonitor) {
        this.plugin = plugin;
        this.logger = plugin.getLogger();
        this.connectionTracker = connectionTracker;
        this.ipManager = ipManager;
        this.packetMonitor = packetMonitor;
        
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
        
        for (UUID playerId : activeConsoles.keySet()) {
            Player player = Bukkit.getPlayer(playerId);
            if (player != null && player.isOnline()) {
                player.closeInventory();
            }
        }
        
        activeConsoles.clear();
        playerPages.clear();
        ipInspections.clear();
    }
    
    private void startRefreshTask() {
        refreshTask = Bukkit.getScheduler().runTaskTimer(plugin, () -> {
            for (UUID playerId : activeConsoles.keySet()) {
                Player player = Bukkit.getPlayer(playerId);
                if (player != null && player.isOnline()) {
                    refreshPlayerConsole(player);
                } else {
                    activeConsoles.remove(playerId);
                    playerPages.remove(playerId);
                    ipInspections.remove(playerId);
                }
            }
        }, 20L, 20L); 
    }
    
    private void refreshPlayerConsole(Player player) {
        String page = playerPages.getOrDefault(player.getUniqueId(), "main");
        
        switch (page) {
            case "main":
                updateMainDashboard(player);
                break;
            case "connections":
                openConnectionsPage(player);
                break;
            case "whitelist":
                openWhitelistPage(player);
                break;
            case "blacklist":
                openBlacklistPage(player);
                break;
            case "packets":
                openPacketsPage(player);
                break;
            case "ip_inspect":
                String ip = ipInspections.get(player.getUniqueId());
                if (ip != null) {
                    openIpInspectionPage(player, ip);
                } else {
                    openConnectionsPage(player);
                }
                break;
        }
    }
    
    private Inventory createMainDashboard(Player player) {
        Inventory inventory = Bukkit.createInventory(null, 54, "§8§lNantiDDoS Security Console");
        
        ItemStack header = createGuiItem(Material.NETHER_STAR, "§e§lNantiDDoS Dashboard", 
                "§7View and manage your server's protection", 
                "§7Version: " + plugin.getDescription().getVersion());
        inventory.setItem(4, header);
        
        boolean protectionEnabled = plugin.getConfig().getBoolean("protection.enabled", true);
        ItemStack statusItem = createGuiItem(
            protectionEnabled ? Material.GREEN_WOOL : Material.RED_WOOL,
            protectionEnabled ? "§a§lProtection: ENABLED" : "§c§lProtection: DISABLED",
            "§7Click to " + (protectionEnabled ? "disable" : "enable") + " protection"
        );
        inventory.setItem(19, statusItem);
        
        ItemStack connectionsItem = createGuiItem(Material.COMPASS, "§e§lConnection Monitor", 
                "§7View active connections", 
                "§7Tracked IPs: §a" + connectionTracker.getConnectionsCount(), 
                "§7Suspicious: §c" + connectionTracker.getSuspiciousConnectionsCount());
        inventory.setItem(21, connectionsItem);
        
        ItemStack whitelistItem = createGuiItem(Material.PAPER, "§e§lIP Whitelist", 
                "§7Manage whitelisted IPs and networks", 
                "§7Whitelisted IPs: §a" + ipManager.getWhitelistedIps().size(), 
                "§7Whitelisted Networks: §a" + ipManager.getWhitelistedNetworks().size());
        inventory.setItem(22, whitelistItem);
        
        ItemStack blacklistItem = createGuiItem(Material.BARRIER, "§e§lIP Blacklist", 
                "§7Manage blacklisted IPs and networks", 
                "§7Blacklisted IPs: §c" + ipManager.getBlacklistedIps().size(), 
                "§7Blacklisted Networks: §c" + ipManager.getBlacklistedNetworks().size());
        inventory.setItem(23, blacklistItem);
        
        ItemStack packetItem = createGuiItem(Material.REPEATER, "§e§lPacket Analysis", 
                "§7View packet statistics", 
                "§7Full Analysis: " + (packetMonitor.isPacketMonitoringFullyAvailable() ? "§aYes" : "§cNo"),
                "§7Suspicious Sources: §c" + packetMonitor.getSuspiciousPacketSources());
        inventory.setItem(25, packetItem);
        
        ItemStack clearDataItem = createGuiItem(Material.WATER_BUCKET, "§c§lClear Data", 
                "§7Click to clear all connection data");
        inventory.setItem(40, clearDataItem);
        
        ItemStack closeItem = createGuiItem(Material.BARRIER, "§c§lClose", 
                "§7Close the security console");
        inventory.setItem(49, closeItem);
        
        fillEmptySlots(inventory);
        return inventory;
    }
    
    private void updateMainDashboard(Player player) {
        Inventory inventory = activeConsoles.get(player.getUniqueId());
        
        boolean protectionEnabled = plugin.getConfig().getBoolean("protection.enabled", true);
        ItemStack statusItem = createGuiItem(
            protectionEnabled ? Material.GREEN_WOOL : Material.RED_WOOL,
            protectionEnabled ? "§a§lProtection: ENABLED" : "§c§lProtection: DISABLED",
            "§7Click to " + (protectionEnabled ? "disable" : "enable") + " protection"
        );
        inventory.setItem(19, statusItem);
        
        ItemStack connectionsItem = createGuiItem(Material.COMPASS, "§e§lConnection Monitor", 
                "§7View active connections", 
                "§7Tracked IPs: §a" + connectionTracker.getConnectionsCount(), 
                "§7Suspicious: §c" + connectionTracker.getSuspiciousConnectionsCount());
        inventory.setItem(21, connectionsItem);
        
        ItemStack whitelistItem = createGuiItem(Material.PAPER, "§e§lIP Whitelist", 
                "§7Manage whitelisted IPs and networks", 
                "§7Whitelisted IPs: §a" + ipManager.getWhitelistedIps().size(), 
                "§7Whitelisted Networks: §a" + ipManager.getWhitelistedNetworks().size());
        inventory.setItem(22, whitelistItem);
        
        ItemStack blacklistItem = createGuiItem(Material.BARRIER, "§e§lIP Blacklist", 
                "§7Manage blacklisted IPs and networks", 
                "§7Blacklisted IPs: §c" + ipManager.getBlacklistedIps().size(), 
                "§7Blacklisted Networks: §c" + ipManager.getBlacklistedNetworks().size());
        inventory.setItem(23, blacklistItem);
        
        ItemStack packetItem = createGuiItem(Material.REPEATER, "§e§lPacket Analysis", 
                "§7View packet statistics", 
                "§7Full Analysis: " + (packetMonitor.isPacketMonitoringFullyAvailable() ? "§aYes" : "§cNo"),
                "§7Suspicious Sources: §c" + packetMonitor.getSuspiciousPacketSources());
        inventory.setItem(25, packetItem);
    }
    
    private void openConnectionsPage(Player player) {
        playerPages.put(player.getUniqueId(), "connections");
        
        Inventory inventory = Bukkit.createInventory(null, 54, "§8§lConnections Monitor");
        
        ItemStack header = createGuiItem(Material.COMPASS, "§e§lConnection Monitor", 
                "§7View all connections being tracked",
                "§7Total tracked IPs: §a" + connectionTracker.getConnectionsCount());
        inventory.setItem(4, header);
        
        ItemStack backButton = createGuiItem(Material.ARROW, "§c§lBack", 
                "§7Return to main dashboard");
        inventory.setItem(49, backButton);
        
        Map<String, ConnectionTracker.ConnectionData> connections = connectionTracker.getConnectionMap();
        Map<String, Integer> botScores = connectionTracker.getBotScores();
        
        int slot = 9;
        for (Map.Entry<String, ConnectionTracker.ConnectionData> entry : connections.entrySet().stream()
                .sorted((e1, e2) -> botScores.getOrDefault(e2.getKey(), 0) - botScores.getOrDefault(e1.getKey(), 0))
                .limit(36)
                .collect(Collectors.toList())) {
                
            String ip = entry.getKey();
            ConnectionTracker.ConnectionData data = entry.getValue();
            int botScore = botScores.getOrDefault(ip, 0);
            
            Material itemType;
            if (botScore >= 20) {
                itemType = Material.RED_CONCRETE;
            } else if (botScore >= 10) {
                itemType = Material.YELLOW_CONCRETE;
            } else {
                itemType = Material.LIME_CONCRETE;
            }
            
            String firstSeen = dateFormat.format(new Date(data.getFirstConnectionTime()));
            String lastSeen = dateFormat.format(new Date(data.getLastConnectionTime()));
            
            ItemStack ipItem = createGuiItem(itemType, "§e§l" + ip, 
                    "§7Bot Score: " + formatBotScoreColor(botScore),
                    "§7First Seen: §f" + firstSeen,
                    "§7Last Seen: §f" + lastSeen,
                    "§7Pings: §f" + data.getPingCount(),
                    "§7Logins: §f" + data.getLoginCount(),
                    "§7Connections/sec: §f" + data.getConnectionsPerSecond(),
                    "",
                    "§eClick to inspect this IP");
            
            inventory.setItem(slot++, ipItem);
            
            if (slot > 44) break;
        }
        
        fillEmptySlots(inventory);
        player.openInventory(inventory);
        activeConsoles.put(player.getUniqueId(), inventory);
    }
    
    private void openWhitelistPage(Player player) {
        playerPages.put(player.getUniqueId(), "whitelist");
        
        Inventory inventory = Bukkit.createInventory(null, 54, "§8§lIP Whitelist Manager");
        
        ItemStack header = createGuiItem(Material.PAPER, "§e§lIP Whitelist", 
                "§7Manage whitelisted IPs and networks",
                "§7Total whitelisted IPs: §a" + ipManager.getWhitelistedIps().size());
        inventory.setItem(4, header);
        
        ItemStack addItem = createGuiItem(Material.EMERALD_BLOCK, "§a§lAdd IP to Whitelist", 
                "§7Click to add a new IP to whitelist",
                "§7You will be prompted in chat");
        inventory.setItem(48, addItem);
        
        ItemStack backButton = createGuiItem(Material.ARROW, "§c§lBack", 
                "§7Return to main dashboard");
        inventory.setItem(49, backButton);
        
        int slot = 9;
        for (String ip : ipManager.getWhitelistedIps()) {
            ItemStack ipItem = createGuiItem(Material.LIME_CONCRETE, "§a§l" + ip, 
                    "§7Type: §fSingle IP",
                    "",
                    "§eClick to remove from whitelist");
            
            inventory.setItem(slot++, ipItem);
            
            if (slot > 44) break;
        }
        
        for (String network : ipManager.getWhitelistedNetworks()) {
            ItemStack ipItem = createGuiItem(Material.LIME_TERRACOTTA, "§a§l" + network, 
                    "§7Type: §fNetwork (CIDR)",
                    "",
                    "§eClick to remove from whitelist");
            
            inventory.setItem(slot++, ipItem);
            
            if (slot > 44) break;
        }
        
        fillEmptySlots(inventory);
        player.openInventory(inventory);
        activeConsoles.put(player.getUniqueId(), inventory);
    }
    
    private void openBlacklistPage(Player player) {
        playerPages.put(player.getUniqueId(), "blacklist");
        
        Inventory inventory = Bukkit.createInventory(null, 54, "§8§lIP Blacklist Manager");
        
        ItemStack header = createGuiItem(Material.BARRIER, "§e§lIP Blacklist", 
                "§7Manage blacklisted IPs and networks",
                "§7Total blacklisted IPs: §c" + ipManager.getBlacklistedIps().size());
        inventory.setItem(4, header);
        
        ItemStack addItem = createGuiItem(Material.REDSTONE_BLOCK, "§c§lAdd IP to Blacklist", 
                "§7Click to add a new IP to blacklist",
                "§7You will be prompted in chat");
        inventory.setItem(48, addItem);
        
        ItemStack backButton = createGuiItem(Material.ARROW, "§c§lBack", 
                "§7Return to main dashboard");
        inventory.setItem(49, backButton);
        
        int slot = 9;
        for (String ip : ipManager.getBlacklistedIps()) {
            ItemStack ipItem = createGuiItem(Material.RED_CONCRETE, "§c§l" + ip, 
                    "§7Type: §fSingle IP",
                    "",
                    "§eClick to remove from blacklist");
            
            inventory.setItem(slot++, ipItem);
            
            if (slot > 44) break;
        }
        
        for (String network : ipManager.getBlacklistedNetworks()) {
            ItemStack ipItem = createGuiItem(Material.RED_TERRACOTTA, "§c§l" + network, 
                    "§7Type: §fNetwork (CIDR)",
                    "",
                    "§eClick to remove from blacklist");
            
            inventory.setItem(slot++, ipItem);
            
            if (slot > 44) break;
        }
        
        fillEmptySlots(inventory);
        player.openInventory(inventory);
        activeConsoles.put(player.getUniqueId(), inventory);
    }
    
    private void openPacketsPage(Player player) {
        playerPages.put(player.getUniqueId(), "packets");
        
        Inventory inventory = Bukkit.createInventory(null, 54, "§8§lPacket Analysis");
        
        boolean fullAnalysis = packetMonitor.isPacketMonitoringFullyAvailable();
        
        ItemStack header = createGuiItem(Material.REPEATER, "§e§lPacket Analysis", 
                "§7Monitor packet activities",
                "§7Full analysis: " + (fullAnalysis ? "§aEnabled" : "§cDisabled (ProtocolLib not found)"),
                "§7Suspicious sources: §c" + packetMonitor.getSuspiciousPacketSources());
        inventory.setItem(4, header);
        
        int activeSessions = packetMonitor.getActivePacketMonitoringSessions();
        ItemStack sessionsItem = createGuiItem(Material.CLOCK, "§e§lMonitoring Sessions", 
                "§7Active packet monitoring sessions: §a" + activeSessions);
        inventory.setItem(20, sessionsItem);
        
        int suspiciousSources = packetMonitor.getSuspiciousPacketSources();
        Material threatMaterial = suspiciousSources > 0 ? Material.RED_CONCRETE : Material.LIME_CONCRETE;
        ItemStack threatItem = createGuiItem(threatMaterial, "§e§lThreat Assessment", 
                "§7Suspicious packet sources: §c" + suspiciousSources,
                "§7Threat level: " + (suspiciousSources > 5 ? "§c§lHIGH" : suspiciousSources > 0 ? "§e§lMEDIUM" : "§a§lLOW"));
        inventory.setItem(22, threatItem);
        
        boolean autobanEnabled = plugin.getConfig().getBoolean("protection.packet-analysis.autoban-enabled", false);
        ItemStack autobanItem = createGuiItem(
            autobanEnabled ? Material.REDSTONE_TORCH : Material.LEVER,
            autobanEnabled ? "§c§lAutoban: ENABLED" : "§7§lAutoban: DISABLED",
            "§7Click to " + (autobanEnabled ? "disable" : "enable") + " automatic banning",
            "§7When enabled, severe packet abusers will be automatically blacklisted"
        );
        inventory.setItem(24, autobanItem);
        
        ItemStack kickAllItem = createGuiItem(Material.FIRE_CHARGE, "§c§lKick Suspicious Players", 
                "§7Click to kick all players sending suspicious packets",
                "§c§lWARNING: This will kick all suspicious players!");
        inventory.setItem(40, kickAllItem);
        
        ItemStack backButton = createGuiItem(Material.ARROW, "§c§lBack", 
                "§7Return to main dashboard");
        inventory.setItem(49, backButton);
        
        fillEmptySlots(inventory);
        player.openInventory(inventory);
        activeConsoles.put(player.getUniqueId(), inventory);
    }
    
    private void openIpInspectionPage(Player player, String ip) {
        playerPages.put(player.getUniqueId(), "ip_inspect");
        ipInspections.put(player.getUniqueId(), ip);
        
        Inventory inventory = Bukkit.createInventory(null, 54, "§8§lInspecting IP: " + ip);
        
        ConnectionTracker.ConnectionData data = connectionTracker.getConnectionMap().get(ip);
        int botScore = connectionTracker.getBotScores().getOrDefault(ip, 0);
        
        if (data == null) {
            player.sendMessage(ChatColor.RED + "That IP is no longer being tracked.");
            openConnectionsPage(player);
            return;
        }
        
        Material headerMaterial = Material.COMPASS;
        if (botScore >= 20) {
            headerMaterial = Material.RED_CONCRETE;
        } else if (botScore >= 10) {
            headerMaterial = Material.YELLOW_CONCRETE;
        } else {
            headerMaterial = Material.LIME_CONCRETE;
        }
        
        String firstSeen = dateFormat.format(new Date(data.getFirstConnectionTime()));
        String lastSeen = dateFormat.format(new Date(data.getLastConnectionTime()));
        
        ItemStack header = createGuiItem(headerMaterial, "§e§l" + ip, 
                "§7Bot Score: " + formatBotScoreColor(botScore),
                "§7First Seen: §f" + firstSeen,
                "§7Last Seen: §f" + lastSeen,
                "§7Pings: §f" + data.getPingCount(),
                "§7Logins: §f" + data.getLoginCount(),
                "§7Chat Messages: §f" + data.getChatMessageCount(),
                "§7Commands: §f" + data.getCommandCount());
        inventory.setItem(4, header);
        
        boolean isWhitelisted = ipManager.isWhitelisted(ip);
        boolean isBlacklisted = ipManager.isBlacklisted(ip);
        
        ItemStack whitelistItem = createGuiItem(
            isWhitelisted ? Material.EMERALD_BLOCK : Material.EMERALD_ORE,
            isWhitelisted ? "§a§lWhitelisted" : "§7§lAdd to Whitelist",
            isWhitelisted ? "§7This IP is whitelisted" : "§7Click to add to whitelist",
            isWhitelisted ? "§7Click to remove from whitelist" : "§7Whitelisted IPs bypass throttling"
        );
        inventory.setItem(19, whitelistItem);
        
        ItemStack blacklistItem = createGuiItem(
            isBlacklisted ? Material.REDSTONE_BLOCK : Material.REDSTONE_ORE,
            isBlacklisted ? "§c§lBlacklisted" : "§7§lAdd to Blacklist",
            isBlacklisted ? "§7This IP is blacklisted" : "§7Click to add to blacklist",
            isBlacklisted ? "§7Click to remove from blacklist" : "§7Blacklisted IPs are always blocked"
        );
        inventory.setItem(21, blacklistItem);
        
        ItemStack clearDataItem = createGuiItem(Material.WATER_BUCKET, "§c§lClear Data for this IP", 
                "§7Click to clear all connection data for this IP");
        inventory.setItem(23, clearDataItem);
        
        ItemStack lookupItem = createGuiItem(Material.SPYGLASS, "§e§lIP Lookup", 
                "§7Click to look up this IP in external databases");
        inventory.setItem(25, lookupItem);
        
        UUID playerId = data.getLastPlayerId();
        if (playerId != null) {
            Player associatedPlayer = Bukkit.getPlayer(playerId);
            String playerName = associatedPlayer != null ? associatedPlayer.getName() : "Unknown";
            
            ItemStack playerItem = createGuiItem(Material.PLAYER_HEAD, "§e§lAssociated Player", 
                    "§7Last player: §f" + playerName,
                    "§7Player UUID: §f" + playerId);
            inventory.setItem(40, playerItem);
        }
        
        ItemStack backButton = createGuiItem(Material.ARROW, "§c§lBack", 
                "§7Return to connections list");
        inventory.setItem(49, backButton);
        
        fillEmptySlots(inventory);
        player.openInventory(inventory);
        activeConsoles.put(player.getUniqueId(), inventory);
    }
    
    private void promptAddWhitelist(Player player) {
        player.closeInventory();
        player.sendMessage(ChatColor.GREEN + "Please enter the IP address or CIDR notation to add to the whitelist in chat:");
        player.sendMessage(ChatColor.GRAY + "Example: 192.168.1.1 or 192.168.1.0/24");
        
        Bukkit.getScheduler().runTaskLater(plugin, () -> {
            Bukkit.getPluginManager().registerEvents(new InputListener(player.getUniqueId(), input -> {
                if (ipManager.addToWhitelist(input)) {
                    player.sendMessage(ChatColor.GREEN + "Added " + input + " to whitelist successfully!");
                } else {
                    player.sendMessage(ChatColor.RED + "Invalid IP address or CIDR notation: " + input);
                }
                
                Bukkit.getScheduler().runTaskLater(plugin, () -> {
                    openWhitelistPage(player);
                }, 20L);
                
                return true;
            }), plugin);
        }, 5L);
    }
    
    private void promptAddBlacklist(Player player) {
        player.closeInventory();
        player.sendMessage(ChatColor.GREEN + "Please enter the IP address or CIDR notation to add to the blacklist in chat:");
        player.sendMessage(ChatColor.GRAY + "Example: 192.168.1.1 or 192.168.1.0/24");
        
        Bukkit.getScheduler().runTaskLater(plugin, () -> {
            Bukkit.getPluginManager().registerEvents(new InputListener(player.getUniqueId(), input -> {
                if (ipManager.addToBlacklist(input)) {
                    player.sendMessage(ChatColor.GREEN + "Added " + input + " to blacklist successfully!");
                } else {
                    player.sendMessage(ChatColor.RED + "Invalid IP address or CIDR notation: " + input);
                }
                
                Bukkit.getScheduler().runTaskLater(plugin, () -> {
                    openBlacklistPage(player);
                }, 20L);
                
                return true;
            }), plugin);
        }, 5L);
    }
    
    private void kickSuspiciousPlayers(Player admin) {
        int kicked = 0;
        for (Player player : Bukkit.getOnlinePlayers()) {
            if (player.getUniqueId().equals(admin.getUniqueId())) continue;
            
            if (player.getAddress() != null) {
                String ip = player.getAddress().getAddress().getHostAddress();
                int botScore = connectionTracker.getBotScores().getOrDefault(ip, 0);
                
                if (botScore >= 20) {
                    player.kickPlayer(plugin.getConfig().getString("messages.packet-flood-message", 
                            "§c§lYou have been kicked for sending too many packets to the server."));
                    kicked++;
                }
            }
        }
        
        admin.sendMessage(ChatColor.GREEN + "Kicked " + kicked + " suspicious players.");
    }
    
    @EventHandler
    public void onInventoryClick(InventoryClickEvent event) {
        Player player = (Player) event.getWhoClicked();
        UUID playerId = player.getUniqueId();
        
        if (!activeConsoles.containsKey(playerId)) {
            return;
        }
        
        event.setCancelled(true);
        
        if (event.getCurrentItem() == null || event.getCurrentItem().getType() == Material.AIR) {
            return;
        }
        
        ItemStack clickedItem = event.getCurrentItem();
        String page = playerPages.getOrDefault(playerId, "main");
        
        if (clickedItem.getType() == Material.ARROW && clickedItem.getItemMeta().getDisplayName().contains("Back")) {
            if (page.equals("ip_inspect")) {
                openConnectionsPage(player);
            } else {
                openDashboard(player);
            }
            player.playSound(player.getLocation(), Sound.UI_BUTTON_CLICK, 0.5f, 1.0f);
            return;
        }
        
        if (page.equals("main")) {
            handleMainPageClick(player, clickedItem, event.getSlot());
        } else if (page.equals("connections")) {
            handleConnectionsPageClick(player, clickedItem);
        } else if (page.equals("whitelist")) {
            handleWhitelistPageClick(player, clickedItem, event.getSlot());
        } else if (page.equals("blacklist")) {
            handleBlacklistPageClick(player, clickedItem, event.getSlot());
        } else if (page.equals("packets")) {
            handlePacketsPageClick(player, clickedItem, event.getSlot());
        } else if (page.equals("ip_inspect")) {
            handleIpInspectPageClick(player, clickedItem, event.getSlot());
        }
    }
    
    private void handleMainPageClick(Player player, ItemStack clickedItem, int slot) {
        if (slot == 19) {
            boolean currentStatus = plugin.getConfig().getBoolean("protection.enabled", true);
            plugin.getConfig().set("protection.enabled", !currentStatus);
            plugin.saveConfig();
            
            if (connectionTracker != null) {
                connectionTracker.enableProtection(!currentStatus);
            }
            
            if (packetMonitor != null) {
                packetMonitor.enableProtection(!currentStatus);
            }
            
            player.sendMessage(ChatColor.GREEN + "Protection " + (!currentStatus ? "enabled" : "disabled") + "!");
            updateMainDashboard(player);
        } else if (slot == 21) {
            openConnectionsPage(player);
        } else if (slot == 22) {
            openWhitelistPage(player);
        } else if (slot == 23) {
            openBlacklistPage(player);
        } else if (slot == 25) {
            openPacketsPage(player);
        } else if (slot == 40) {
            if (connectionTracker != null) {
                connectionTracker.clearData();
            }
            player.sendMessage(ChatColor.GREEN + "Connection data cleared!");
        } else if (slot == 49) {
            player.closeInventory();
        }
        
        player.playSound(player.getLocation(), Sound.UI_BUTTON_CLICK, 0.5f, 1.0f);
    }
    
    private void handleConnectionsPageClick(Player player, ItemStack clickedItem) {
        String displayName = ChatColor.stripColor(clickedItem.getItemMeta().getDisplayName());
        
        if (clickedItem.getType() == Material.LIME_CONCRETE || 
            clickedItem.getType() == Material.YELLOW_CONCRETE || 
            clickedItem.getType() == Material.RED_CONCRETE) {
            
            openIpInspectionPage(player, displayName);
        }
        
        player.playSound(player.getLocation(), Sound.UI_BUTTON_CLICK, 0.5f, 1.0f);
    }
    
    private void handleWhitelistPageClick(Player player, ItemStack clickedItem, int slot) {
        if (slot == 48) {
            promptAddWhitelist(player);
            return;
        }
        
        String displayName = ChatColor.stripColor(clickedItem.getItemMeta().getDisplayName());
        
        if (clickedItem.getType() == Material.LIME_CONCRETE || 
            clickedItem.getType() == Material.LIME_TERRACOTTA) {
            
            if (ipManager.removeFromWhitelist(displayName)) {
                player.sendMessage(ChatColor.GREEN + "Removed " + displayName + " from whitelist!");
                openWhitelistPage(player);
            }
        }
        
        player.playSound(player.getLocation(), Sound.UI_BUTTON_CLICK, 0.5f, 1.0f);
    }
    
    private void handleBlacklistPageClick(Player player, ItemStack clickedItem, int slot) {
        if (slot == 48) {
            promptAddBlacklist(player);
            return;
        }
        
        String displayName = ChatColor.stripColor(clickedItem.getItemMeta().getDisplayName());
        
        if (clickedItem.getType() == Material.RED_CONCRETE || 
            clickedItem.getType() == Material.RED_TERRACOTTA) {
            
            if (ipManager.removeFromBlacklist(displayName)) {
                player.sendMessage(ChatColor.GREEN + "Removed " + displayName + " from blacklist!");
                openBlacklistPage(player);
            }
        }
        
        player.playSound(player.getLocation(), Sound.UI_BUTTON_CLICK, 0.5f, 1.0f);
    }
    
    private void handlePacketsPageClick(Player player, ItemStack clickedItem, int slot) {
        if (slot == 24) {
            boolean currentStatus = plugin.getConfig().getBoolean("protection.packet-analysis.autoban-enabled", false);
            plugin.getConfig().set("protection.packet-analysis.autoban-enabled", !currentStatus);
            plugin.saveConfig();
            
            player.sendMessage(ChatColor.GREEN + "Autoban " + (!currentStatus ? "enabled" : "disabled") + "!");
            openPacketsPage(player);
        } else if (slot == 40) {
            kickSuspiciousPlayers(player);
            openPacketsPage(player);
        }
        
        player.playSound(player.getLocation(), Sound.UI_BUTTON_CLICK, 0.5f, 1.0f);
    }
    
    private void handleIpInspectPageClick(Player player, ItemStack clickedItem, int slot) {
        String ip = ipInspections.get(player.getUniqueId());
        
        if (ip == null) {
            openConnectionsPage(player);
            return;
        }
        
        if (slot == 19) {
            if (ipManager.isWhitelisted(ip)) {
                ipManager.removeFromWhitelist(ip);
                player.sendMessage(ChatColor.GREEN + "Removed " + ip + " from whitelist!");
            } else {
                ipManager.addToWhitelist(ip);
                player.sendMessage(ChatColor.GREEN + "Added " + ip + " to whitelist!");
            }
            openIpInspectionPage(player, ip);
        } else if (slot == 21) {
            if (ipManager.isBlacklisted(ip)) {
                ipManager.removeFromBlacklist(ip);
                player.sendMessage(ChatColor.GREEN + "Removed " + ip + " from blacklist!");
            } else {
                ipManager.addToBlacklist(ip);
                player.sendMessage(ChatColor.GREEN + "Added " + ip + " to blacklist!");
            }
            openIpInspectionPage(player, ip);
        } else if (slot == 23) {
            connectionTracker.clearData(ip);
            player.sendMessage(ChatColor.GREEN + "Cleared data for IP: " + ip);
            openConnectionsPage(player);
        } else if (slot == 25) {
            player.closeInventory();
            player.sendMessage(ChatColor.GREEN + "IP Lookup for: " + ip);
            player.sendMessage(ChatColor.GRAY + "https://ipinfo.io/" + ip);
        }
        
        player.playSound(player.getLocation(), Sound.UI_BUTTON_CLICK, 0.5f, 1.0f);
    }
    
    @EventHandler
    public void onInventoryClose(InventoryCloseEvent event) {
        Player player = (Player) event.getPlayer();
        UUID playerId = player.getUniqueId();
        
        if (activeConsoles.containsKey(playerId) && !playerPages.getOrDefault(playerId, "").equals("ip_add")) {
            Bukkit.getScheduler().runTaskLater(plugin, () -> {
                activeConsoles.remove(playerId);
            }, 5L);
        }
    }
    
    private ItemStack createGuiItem(Material material, String name, String... lore) {
        ItemStack item = new ItemStack(material, 1);
        ItemMeta meta = item.getItemMeta();
        
        meta.setDisplayName(name);
        
        if (lore.length > 0) {
            List<String> loreList = new ArrayList<>(Arrays.asList(lore));
            meta.setLore(loreList);
        }
        
        meta.addItemFlags(ItemFlag.HIDE_ATTRIBUTES);
        meta.addItemFlags(ItemFlag.HIDE_ENCHANTS);
        item.setItemMeta(meta);
        
        return item;
    }
    
    private ItemStack createGlowingItem(Material material, String name, String... lore) {
        ItemStack item = createGuiItem(material, name, lore);
        ItemMeta meta = item.getItemMeta();
        
        meta.addEnchant(Enchantment.UNBREAKING, 1, true);
        meta.addItemFlags(ItemFlag.HIDE_ENCHANTS);
        item.setItemMeta(meta);
        
        return item;
    }
    
    private void fillEmptySlots(Inventory inventory) {
        ItemStack filler = createGuiItem(Material.BLACK_STAINED_GLASS_PANE, " ");
        
        for (int i = 0; i < inventory.getSize(); i++) {
            if (inventory.getItem(i) == null || inventory.getItem(i).getType() == Material.AIR) {
                inventory.setItem(i, filler);
            }
        }
    }
    
    private String formatBotScoreColor(int score) {
        if (score >= 20) {
            return "§c" + score + " (High Risk)";
        } else if (score >= 10) {
            return "§e" + score + " (Suspicious)";
        } else {
            return "§a" + score + " (Normal)";
        }
    }
    
    private class InputListener implements org.bukkit.event.Listener {
        private final UUID playerId;
        private final java.util.function.Function<String, Boolean> callback;
        
        public InputListener(UUID playerId, java.util.function.Function<String, Boolean> callback) {
            this.playerId = playerId;
            this.callback = callback;
        }
        
        @EventHandler
        public void onPlayerChat(org.bukkit.event.player.AsyncPlayerChatEvent event) {
            if (event.getPlayer().getUniqueId().equals(playerId)) {
                event.setCancelled(true);
                
                if (callback.apply(event.getMessage())) {
                    org.bukkit.event.HandlerList.unregisterAll(this);
                }
            }
        }
    }
}