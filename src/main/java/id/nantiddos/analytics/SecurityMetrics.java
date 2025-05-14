package id.nantiddos.analytics;

import id.nantiddos.Nantiddos;
import id.nantiddos.protection.AttackDetector;
import id.nantiddos.protection.ConnectionTracker;
import id.nantiddos.protection.IPManager;
import id.nantiddos.protection.AttackDetector.AttackType;
import id.nantiddos.protection.AttackDetector.AlertLevel;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.text.SimpleDateFormat;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Date;
import java.util.EnumMap;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import java.util.logging.Logger;

import org.bukkit.Bukkit;
import org.bukkit.ChatColor;
import org.bukkit.configuration.ConfigurationSection;
import org.bukkit.configuration.file.FileConfiguration;
import org.bukkit.entity.Player;
import org.bukkit.scheduler.BukkitTask;

public class SecurityMetrics {
    private final Nantiddos plugin;
    private final Logger logger;
    private final AttackDetector attackDetector;
    private final ConnectionTracker connectionTracker;
    private final IPManager ipManager;
    
    private Connection database;
    private final File dataFolder;
    private final File metricsFolder;
    private final File reportsFolder;
    private final DateTimeFormatter dateFormat = DateTimeFormatter.ofPattern("yyyy-MM-dd");
    private final DateTimeFormatter timeFormat = DateTimeFormatter.ofPattern("HH:mm:ss");
    private final DateTimeFormatter fileFormat = DateTimeFormatter.ofPattern("yyyy-MM-dd_HH-mm-ss");
    private final SimpleDateFormat reportDateFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
    
    private BukkitTask dataCollectionTask;
    private BukkitTask dailyReportTask;
    private BukkitTask weeklyReportTask;
    private BukkitTask purgeOldDataTask;
    
    private boolean enabled;
    private boolean enableDatabase;
    private boolean enableCsvExport;
    private boolean enableJsonExport;
    private boolean enableAutoReporting;
    private int dataCollectionIntervalMinutes;
    private int dataRetentionDays;
    private String exportFormat;
    
    private final Map<String, DailyMetrics> dailyMetricsMap = new ConcurrentHashMap<>();
    
    public SecurityMetrics(Nantiddos plugin) {
        this.plugin = plugin;
        this.logger = plugin.getLogger();
        this.attackDetector = plugin.getAttackDetector();
        this.connectionTracker = plugin.getConnectionTracker();
        this.ipManager = plugin.getIpManager();
        
        this.dataFolder = plugin.getDataFolder();
        this.metricsFolder = new File(dataFolder, "metrics");
        this.reportsFolder = new File(dataFolder, "reports");
        
        if (!metricsFolder.exists()) {
            metricsFolder.mkdirs();
        }
        
        if (!reportsFolder.exists()) {
            reportsFolder.mkdirs();
        }
        
        loadConfig();
        initializeMetricsSystem();
    }
    
    public void loadConfig() {
        FileConfiguration config = plugin.getConfig();
        ConfigurationSection section = config.getConfigurationSection("analytics");
        
        if (section == null) {
            enabled = false;
            enableDatabase = false;
            enableCsvExport = true;
            enableJsonExport = false;
            enableAutoReporting = true;
            dataCollectionIntervalMinutes = 15;
            dataRetentionDays = 30;
            exportFormat = "csv";
            return;
        }
        
        enabled = section.getBoolean("enabled", true);
        enableDatabase = section.getBoolean("enable-database", false);
        enableCsvExport = section.getBoolean("enable-csv-export", true);
        enableJsonExport = section.getBoolean("enable-json-export", false);
        enableAutoReporting = section.getBoolean("enable-auto-reporting", true);
        dataCollectionIntervalMinutes = section.getInt("data-collection-interval-minutes", 15);
        dataRetentionDays = section.getInt("data-retention-days", 30);
        exportFormat = section.getString("export-format", "csv").toLowerCase();
    }
    
    private void initializeMetricsSystem() {
        if (!enabled) {
            logger.info("Analytics and reporting system is disabled");
            return;
        }
        
        if (enableDatabase) {
            initializeDatabase();
        }
        
        startDataCollection();
        startScheduledTasks();
        
        logger.info("Analytics and reporting system initialized");
    }
    
    private void initializeDatabase() {
        try {
            File dbFile = new File(dataFolder, "security_metrics.db");
            String url = "jdbc:sqlite:" + dbFile.getAbsolutePath();
            
            database = DriverManager.getConnection(url);
            
            try (Statement stmt = database.createStatement()) {
                String createMetricsTable = "CREATE TABLE IF NOT EXISTS metrics (" +
                    "id INTEGER PRIMARY KEY AUTOINCREMENT," +
                    "timestamp TEXT NOT NULL," +
                    "connections_count INTEGER," +
                    "suspicious_count INTEGER," +
                    "blacklisted_count INTEGER," +
                    "whitelisted_count INTEGER," +
                    "threat_level INTEGER," +
                    "max_connections_per_sec INTEGER" +
                    ")";
                
                String createAttacksTable = "CREATE TABLE IF NOT EXISTS attacks (" +
                    "id INTEGER PRIMARY KEY AUTOINCREMENT," +
                    "timestamp TEXT NOT NULL," +
                    "attack_type TEXT NOT NULL," +
                    "source_ips TEXT NOT NULL," +
                    "alert_level TEXT NOT NULL," +
                    "duration_seconds INTEGER," +
                    "max_threat_score INTEGER" +
                    ")";
                
                String createReportsTable = "CREATE TABLE IF NOT EXISTS reports (" +
                    "id INTEGER PRIMARY KEY AUTOINCREMENT," +
                    "timestamp TEXT NOT NULL," +
                    "report_type TEXT NOT NULL," +
                    "start_date TEXT NOT NULL," +
                    "end_date TEXT NOT NULL," +
                    "file_path TEXT NOT NULL" +
                    ")";
                
                stmt.execute(createMetricsTable);
                stmt.execute(createAttacksTable);
                stmt.execute(createReportsTable);
            }
            
            logger.info("Database initialized successfully");
        } catch (SQLException e) {
            logger.severe("Failed to initialize database: " + e.getMessage());
            enableDatabase = false;
        }
    }
    
    public void shutdown() {
        if (dataCollectionTask != null && !dataCollectionTask.isCancelled()) {
            dataCollectionTask.cancel();
        }
        
        if (dailyReportTask != null && !dailyReportTask.isCancelled()) {
            dailyReportTask.cancel();
        }
        
        if (weeklyReportTask != null && !weeklyReportTask.isCancelled()) {
            weeklyReportTask.cancel();
        }
        
        if (purgeOldDataTask != null && !purgeOldDataTask.isCancelled()) {
            purgeOldDataTask.cancel();
        }
        
        if (database != null) {
            try {
                database.close();
            } catch (SQLException e) {
                logger.warning("Error closing database connection: " + e.getMessage());
            }
        }
        
        saveMetricsData();
    }
    
    private void startDataCollection() {
        long intervalTicks = dataCollectionIntervalMinutes * 60L * 20L;
        
        dataCollectionTask = Bukkit.getScheduler().runTaskTimerAsynchronously(plugin, () -> {
            if (!enabled) return;
            
            collectMetricsData();
        }, 100L, intervalTicks);
    }
    
    private void startScheduledTasks() {
        if (!enableAutoReporting) return;
        
        long currentTime = System.currentTimeMillis();
        
        LocalDateTime now = LocalDateTime.now();
        LocalDateTime nextMidnight = now.plusDays(1).withHour(0).withMinute(0).withSecond(0);
        long millisecondsUntilMidnight = ChronoUnit.MILLIS.between(now, nextMidnight);
        long ticksUntilMidnight = millisecondsUntilMidnight / 50;
        
        dailyReportTask = Bukkit.getScheduler().runTaskTimerAsynchronously(plugin, 
            this::generateDailyReport, ticksUntilMidnight, 24 * 60 * 60 * 20L);
        
        int dayOfWeek = now.getDayOfWeek().getValue();
        int daysUntilSunday = 7 - dayOfWeek;
        
        LocalDateTime nextSunday = now.plusDays(daysUntilSunday).withHour(1).withMinute(0).withSecond(0);
        long millisecondsUntilSunday = ChronoUnit.MILLIS.between(now, nextSunday);
        long ticksUntilSunday = millisecondsUntilSunday / 50;
        
        weeklyReportTask = Bukkit.getScheduler().runTaskTimerAsynchronously(plugin,
            this::generateWeeklyReport, ticksUntilSunday, 7 * 24 * 60 * 60 * 20L);
        
        purgeOldDataTask = Bukkit.getScheduler().runTaskTimerAsynchronously(plugin,
            this::purgeOldData, ticksUntilMidnight + (60 * 20), 24 * 60 * 60 * 20L);
    }
    
    private void collectMetricsData() {
        LocalDate today = LocalDate.now();
        String dateKey = today.format(dateFormat);
        
        DailyMetrics metrics = dailyMetricsMap.computeIfAbsent(dateKey, k -> new DailyMetrics(dateKey));
        
        SecuritySnapshot snapshot = new SecuritySnapshot();
        snapshot.timestamp = LocalDateTime.now().format(dateFormat) + " " + LocalDateTime.now().format(timeFormat);
        snapshot.connectionCount = connectionTracker.getConnectionsCount();
        snapshot.suspiciousCount = connectionTracker.getSuspiciousConnectionsCount();
        snapshot.blacklistedCount = ipManager.getBlacklistedIps().size() + ipManager.getBlacklistedNetworks().size();
        snapshot.whitelistedCount = ipManager.getWhitelistedIps().size() + ipManager.getWhitelistedNetworks().size();
        snapshot.threatLevel = attackDetector.getCurrentThreatLevel();
        snapshot.alertLevel = attackDetector.getSystemAlertLevel();
        snapshot.maxConnectionsPerSecond = getMaxConnectionsPerSecond();
        
        metrics.addSnapshot(snapshot);
        
        Map<String, AttackDetector.AttackData> attackDataMap = attackDetector.getAttackDataMap();
        for (Map.Entry<String, AttackDetector.AttackData> entry : attackDataMap.entrySet()) {
            AttackDetector.AttackData data = entry.getValue();
            if (data.getAlertLevel().getLevel() >= AlertLevel.MEDIUM.getLevel()) {
                AttackRecord record = new AttackRecord();
                record.timestamp = snapshot.timestamp;
                record.sourceIp = entry.getKey();
                record.attackType = data.getPrimaryAttackType();
                record.threatScore = data.getCurrentRiskScore();
                record.alertLevel = data.getAlertLevel();
                
                metrics.addAttackRecord(record);
            }
        }
        
        if (enableDatabase) {
            saveMetricsToDatabase(snapshot, metrics.getRecentAttacks());
        }
    }
    
    private void saveMetricsToDatabase(SecuritySnapshot snapshot, List<AttackRecord> attacks) {
        if (database == null) return;
        
        try {
            PreparedStatement stmt = database.prepareStatement(
                "INSERT INTO metrics (timestamp, connections_count, suspicious_count, blacklisted_count, " +
                "whitelisted_count, threat_level, max_connections_per_sec) VALUES (?, ?, ?, ?, ?, ?, ?)");
            
            stmt.setString(1, snapshot.timestamp);
            stmt.setInt(2, snapshot.connectionCount);
            stmt.setInt(3, snapshot.suspiciousCount);
            stmt.setInt(4, snapshot.blacklistedCount);
            stmt.setInt(5, snapshot.whitelistedCount);
            stmt.setInt(6, snapshot.threatLevel);
            stmt.setInt(7, snapshot.maxConnectionsPerSecond);
            
            stmt.executeUpdate();
            stmt.close();
            
            for (AttackRecord attack : attacks) {
                PreparedStatement attackStmt = database.prepareStatement(
                    "INSERT INTO attacks (timestamp, attack_type, source_ips, alert_level, max_threat_score) " +
                    "VALUES (?, ?, ?, ?, ?)");
                
                attackStmt.setString(1, attack.timestamp);
                attackStmt.setString(2, attack.attackType.getName());
                attackStmt.setString(3, attack.sourceIp);
                attackStmt.setString(4, attack.alertLevel.name());
                attackStmt.setInt(5, attack.threatScore);
                
                attackStmt.executeUpdate();
                attackStmt.close();
            }
        } catch (SQLException e) {
            logger.warning("Failed to save metrics to database: " + e.getMessage());
        }
    }
    
    private int getMaxConnectionsPerSecond() {
        int max = 0;
        Map<String, ConnectionTracker.ConnectionData> connections = connectionTracker.getConnectionMap();
        
        for (ConnectionTracker.ConnectionData data : connections.values()) {
            int rate = data.getConnectionsPerSecond();
            if (rate > max) {
                max = rate;
            }
        }
        
        return max;
    }
    
    public void saveMetricsData() {
        for (Map.Entry<String, DailyMetrics> entry : dailyMetricsMap.entrySet()) {
            String date = entry.getKey();
            DailyMetrics metrics = entry.getValue();
            
            if (enableCsvExport) {
                saveDailyMetricsAsCsv(date, metrics);
            }
            
            if (enableJsonExport) {
                saveDailyMetricsAsJson(date, metrics);
            }
        }
    }
    
    private void saveDailyMetricsAsCsv(String date, DailyMetrics metrics) {
        File metricsFile = new File(metricsFolder, date + ".csv");
        
        try (FileWriter writer = new FileWriter(metricsFile)) {
            writer.write("Timestamp,ConnectionCount,SuspiciousCount,BlacklistedCount,WhitelistedCount,ThreatLevel,AlertLevel,MaxConnectionsPerSecond\n");
            
            for (SecuritySnapshot snapshot : metrics.snapshots) {
                writer.write(
                    snapshot.timestamp + "," +
                    snapshot.connectionCount + "," +
                    snapshot.suspiciousCount + "," +
                    snapshot.blacklistedCount + "," +
                    snapshot.whitelistedCount + "," +
                    snapshot.threatLevel + "," +
                    snapshot.alertLevel.name() + "," +
                    snapshot.maxConnectionsPerSecond + "\n"
                );
            }
            
            writer.write("\nAttacks\n");
            writer.write("Timestamp,SourceIP,AttackType,ThreatScore,AlertLevel\n");
            
            for (AttackRecord attack : metrics.attacks) {
                writer.write(
                    attack.timestamp + "," +
                    attack.sourceIp + "," +
                    attack.attackType.getName() + "," +
                    attack.threatScore + "," +
                    attack.alertLevel.name() + "\n"
                );
            }
        } catch (IOException e) {
            logger.warning("Failed to save metrics as CSV: " + e.getMessage());
        }
    }
    
    private void saveDailyMetricsAsJson(String date, DailyMetrics metrics) {
        File metricsFile = new File(metricsFolder, date + ".json");
        
        try (FileWriter writer = new FileWriter(metricsFile)) {
            StringBuilder json = new StringBuilder();
            json.append("{\n");
            json.append("  \"date\": \"").append(date).append("\",\n");
            json.append("  \"metrics\": [\n");
            
            for (int i = 0; i < metrics.snapshots.size(); i++) {
                SecuritySnapshot snapshot = metrics.snapshots.get(i);
                json.append("    {\n");
                json.append("      \"timestamp\": \"").append(snapshot.timestamp).append("\",\n");
                json.append("      \"connectionCount\": ").append(snapshot.connectionCount).append(",\n");
                json.append("      \"suspiciousCount\": ").append(snapshot.suspiciousCount).append(",\n");
                json.append("      \"blacklistedCount\": ").append(snapshot.blacklistedCount).append(",\n");
                json.append("      \"whitelistedCount\": ").append(snapshot.whitelistedCount).append(",\n");
                json.append("      \"threatLevel\": ").append(snapshot.threatLevel).append(",\n");
                json.append("      \"alertLevel\": \"").append(snapshot.alertLevel.name()).append("\",\n");
                json.append("      \"maxConnectionsPerSecond\": ").append(snapshot.maxConnectionsPerSecond).append("\n");
                json.append("    }").append(i < metrics.snapshots.size() - 1 ? ",\n" : "\n");
            }
            
            json.append("  ],\n");
            json.append("  \"attacks\": [\n");
            
            for (int i = 0; i < metrics.attacks.size(); i++) {
                AttackRecord attack = metrics.attacks.get(i);
                json.append("    {\n");
                json.append("      \"timestamp\": \"").append(attack.timestamp).append("\",\n");
                json.append("      \"sourceIp\": \"").append(attack.sourceIp).append("\",\n");
                json.append("      \"attackType\": \"").append(attack.attackType.getName()).append("\",\n");
                json.append("      \"threatScore\": ").append(attack.threatScore).append(",\n");
                json.append("      \"alertLevel\": \"").append(attack.alertLevel.name()).append("\"\n");
                json.append("    }").append(i < metrics.attacks.size() - 1 ? ",\n" : "\n");
            }
            
            json.append("  ]\n");
            json.append("}\n");
            
            writer.write(json.toString());
        } catch (IOException e) {
            logger.warning("Failed to save metrics as JSON: " + e.getMessage());
        }
    }
    
    private void generateDailyReport() {
        LocalDate yesterday = LocalDate.now().minusDays(1);
        String dateKey = yesterday.format(dateFormat);
        
        DailyMetrics metrics = dailyMetricsMap.get(dateKey);
        if (metrics == null) {
            logger.warning("No metrics data available for daily report: " + dateKey);
            return;
        }
        
        String reportName = "daily_report_" + dateKey + "." + exportFormat;
        File reportFile = new File(reportsFolder, reportName);
        
        try {
            generateReport(reportFile, metrics, "Daily Security Report - " + dateKey, dateKey, dateKey);
            logger.info("Daily security report generated: " + reportName);
            
            for (Player player : Bukkit.getOnlinePlayers()) {
                if (player.hasPermission("nantiddos.admin")) {
                    player.sendMessage("§a[NantiDDoS] §eDaily security report generated: §f" + reportName);
                }
            }
            
            recordReportInDatabase("daily", dateKey, dateKey, reportFile.getPath());
        } catch (IOException e) {
            logger.warning("Failed to generate daily report: " + e.getMessage());
        }
    }
    
    private void generateWeeklyReport() {
        LocalDate endDate = LocalDate.now().minusDays(1);
        LocalDate startDate = endDate.minusDays(6);
        
        String startDateStr = startDate.format(dateFormat);
        String endDateStr = endDate.format(dateFormat);
        
        List<DailyMetrics> weekMetrics = new ArrayList<>();
        
        for (int i = 0; i <= 6; i++) {
            LocalDate date = startDate.plusDays(i);
            String dateKey = date.format(dateFormat);
            DailyMetrics metrics = dailyMetricsMap.get(dateKey);
            
            if (metrics != null) {
                weekMetrics.add(metrics);
            }
        }
        
        if (weekMetrics.isEmpty()) {
            logger.warning("No metrics data available for weekly report: " + startDateStr + " to " + endDateStr);
            return;
        }
        
        String reportName = "weekly_report_" + startDateStr + "_to_" + endDateStr + "." + exportFormat;
        File reportFile = new File(reportsFolder, reportName);
        
        try {
            generateWeeklyReportFile(reportFile, weekMetrics, "Weekly Security Report - " + startDateStr + " to " + endDateStr);
            logger.info("Weekly security report generated: " + reportName);
            
            for (Player player : Bukkit.getOnlinePlayers()) {
                if (player.hasPermission("nantiddos.admin")) {
                    player.sendMessage("§a[NantiDDoS] §eWeekly security report generated: §f" + reportName);
                }
            }
            
            recordReportInDatabase("weekly", startDateStr, endDateStr, reportFile.getPath());
        } catch (IOException e) {
            logger.warning("Failed to generate weekly report: " + e.getMessage());
        }
    }
    
    private void generateWeeklyReportFile(File file, List<DailyMetrics> weekMetrics, String title) throws IOException {
        if (exportFormat.equals("csv")) {
            generateWeeklyReportCsv(file, weekMetrics, title);
        } else if (exportFormat.equals("json")) {
            generateWeeklyReportJson(file, weekMetrics, title);
        } else {
            generateWeeklyReportCsv(file, weekMetrics, title);
        }
    }
    
    private void generateWeeklyReportCsv(File file, List<DailyMetrics> weekMetrics, String title) throws IOException {
        try (FileWriter writer = new FileWriter(file)) {
            writer.write(title + "\n\n");
            writer.write("Date,Avg Connection Count,Max Connection Count,Avg Threat Level,Max Threat Level,Total Attacks\n");
            
            for (DailyMetrics dailyMetrics : weekMetrics) {
                int totalConnections = 0;
                int maxConnections = 0;
                int totalThreat = 0;
                int maxThreat = 0;
                
                for (SecuritySnapshot snapshot : dailyMetrics.snapshots) {
                    totalConnections += snapshot.connectionCount;
                    maxConnections = Math.max(maxConnections, snapshot.connectionCount);
                    totalThreat += snapshot.threatLevel;
                    maxThreat = Math.max(maxThreat, snapshot.threatLevel);
                }
                
                double avgConnections = dailyMetrics.snapshots.isEmpty() ? 0 : 
                    (double) totalConnections / dailyMetrics.snapshots.size();
                double avgThreat = dailyMetrics.snapshots.isEmpty() ? 0 : 
                    (double) totalThreat / dailyMetrics.snapshots.size();
                
                writer.write(
                    dailyMetrics.date + "," +
                    String.format("%.2f", avgConnections) + "," +
                    maxConnections + "," +
                    String.format("%.2f", avgThreat) + "," +
                    maxThreat + "," +
                    dailyMetrics.attacks.size() + "\n"
                );
            }
            
            writer.write("\nAttacks by Type\n");
            writer.write("Attack Type,Count\n");
            
            Map<AttackType, Integer> attackTypeCounts = new EnumMap<>(AttackType.class);
            
            for (DailyMetrics dailyMetrics : weekMetrics) {
                for (AttackRecord attack : dailyMetrics.attacks) {
                    attackTypeCounts.put(attack.attackType, 
                        attackTypeCounts.getOrDefault(attack.attackType, 0) + 1);
                }
            }
            
            for (Map.Entry<AttackType, Integer> entry : attackTypeCounts.entrySet()) {
                writer.write(entry.getKey().getName() + "," + entry.getValue() + "\n");
            }
            
            writer.write("\nTop Attack Sources\n");
            writer.write("IP Address,Attack Count\n");
            
            Map<String, Integer> attackSourceCounts = new HashMap<>();
            
            for (DailyMetrics dailyMetrics : weekMetrics) {
                for (AttackRecord attack : dailyMetrics.attacks) {
                    attackSourceCounts.put(attack.sourceIp, 
                        attackSourceCounts.getOrDefault(attack.sourceIp, 0) + 1);
                }
            }
            
            attackSourceCounts.entrySet().stream()
                .sorted(Map.Entry.<String, Integer>comparingByValue().reversed())
                .limit(10)
                .forEach(entry -> {
                    try {
                        writer.write(entry.getKey() + "," + entry.getValue() + "\n");
                    } catch (IOException e) {
                        logger.warning("Error writing to report file: " + e.getMessage());
                    }
                });
        }
    }
    
    private void generateWeeklyReportJson(File file, List<DailyMetrics> weekMetrics, String title) throws IOException {
        try (FileWriter writer = new FileWriter(file)) {
            StringBuilder json = new StringBuilder();
            json.append("{\n");
            json.append("  \"title\": \"").append(title).append("\",\n");
            json.append("  \"generatedAt\": \"").append(LocalDateTime.now().format(DateTimeFormatter.ISO_LOCAL_DATE_TIME)).append("\",\n");
            json.append("  \"dailyMetrics\": [\n");
            
            for (int i = 0; i < weekMetrics.size(); i++) {
                DailyMetrics dailyMetrics = weekMetrics.get(i);
                int totalConnections = 0;
                int maxConnections = 0;
                int totalThreat = 0;
                int maxThreat = 0;
                
                for (SecuritySnapshot snapshot : dailyMetrics.snapshots) {
                    totalConnections += snapshot.connectionCount;
                    maxConnections = Math.max(maxConnections, snapshot.connectionCount);
                    totalThreat += snapshot.threatLevel;
                    maxThreat = Math.max(maxThreat, snapshot.threatLevel);
                }
                
                double avgConnections = dailyMetrics.snapshots.isEmpty() ? 0 : 
                    (double) totalConnections / dailyMetrics.snapshots.size();
                double avgThreat = dailyMetrics.snapshots.isEmpty() ? 0 : 
                    (double) totalThreat / dailyMetrics.snapshots.size();
                
                json.append("    {\n");
                json.append("      \"date\": \"").append(dailyMetrics.date).append("\",\n");
                json.append("      \"avgConnectionCount\": ").append(String.format("%.2f", avgConnections)).append(",\n");
                json.append("      \"maxConnectionCount\": ").append(maxConnections).append(",\n");
                json.append("      \"avgThreatLevel\": ").append(String.format("%.2f", avgThreat)).append(",\n");
                json.append("      \"maxThreatLevel\": ").append(maxThreat).append(",\n");
                json.append("      \"totalAttacks\": ").append(dailyMetrics.attacks.size()).append("\n");
                json.append("    }").append(i < weekMetrics.size() - 1 ? ",\n" : "\n");
            }
            
            json.append("  ],\n");
            
            Map<AttackType, Integer> attackTypeCounts = new EnumMap<>(AttackType.class);
            
            for (DailyMetrics dailyMetrics : weekMetrics) {
                for (AttackRecord attack : dailyMetrics.attacks) {
                    attackTypeCounts.put(attack.attackType, 
                        attackTypeCounts.getOrDefault(attack.attackType, 0) + 1);
                }
            }
            
            json.append("  \"attacksByType\": [\n");
            
            int typeCount = 0;
            for (Map.Entry<AttackType, Integer> entry : attackTypeCounts.entrySet()) {
                json.append("    {\n");
                json.append("      \"attackType\": \"").append(entry.getKey().getName()).append("\",\n");
                json.append("      \"count\": ").append(entry.getValue()).append("\n");
                json.append("    }").append((++typeCount < attackTypeCounts.size()) ? ",\n" : "\n");
            }
            
            json.append("  ],\n");
            
            Map<String, Integer> attackSourceCounts = new HashMap<>();
            
            for (DailyMetrics dailyMetrics : weekMetrics) {
                for (AttackRecord attack : dailyMetrics.attacks) {
                    attackSourceCounts.put(attack.sourceIp, 
                        attackSourceCounts.getOrDefault(attack.sourceIp, 0) + 1);
                }
            }
            
            json.append("  \"topAttackSources\": [\n");
            
            List<Map.Entry<String, Integer>> topSources = attackSourceCounts.entrySet().stream()
                .sorted(Map.Entry.<String, Integer>comparingByValue().reversed())
                .limit(10)
                .toList();
            
            for (int i = 0; i < topSources.size(); i++) {
                Map.Entry<String, Integer> entry = topSources.get(i);
                json.append("    {\n");
                json.append("      \"ip\": \"").append(entry.getKey()).append("\",\n");
                json.append("      \"count\": ").append(entry.getValue()).append("\n");
                json.append("    }").append(i < topSources.size() - 1 ? ",\n" : "\n");
            }
            
            json.append("  ]\n");
            json.append("}\n");
            
            writer.write(json.toString());
        }
    }
    
    private void generateReport(File file, DailyMetrics metrics, String title, String startDate, String endDate) throws IOException {
        if (exportFormat.equals("csv")) {
            generateReportCsv(file, metrics, title);
        } else if (exportFormat.equals("json")) {
            generateReportJson(file, metrics, title);
        } else {
            generateReportCsv(file, metrics, title);
        }
    }
    
    private void generateReportCsv(File file, DailyMetrics metrics, String title) throws IOException {
        try (FileWriter writer = new FileWriter(file)) {
            writer.write(title + "\n\n");
            
            int totalConnections = 0;
            int maxConnections = 0;
            int totalSuspicious = 0;
            int maxSuspicious = 0;
            int totalThreat = 0;
            int maxThreat = 0;
            
            for (SecuritySnapshot snapshot : metrics.snapshots) {
                totalConnections += snapshot.connectionCount;
                maxConnections = Math.max(maxConnections, snapshot.connectionCount);
                totalSuspicious += snapshot.suspiciousCount;
                maxSuspicious = Math.max(maxSuspicious, snapshot.suspiciousCount);
                totalThreat += snapshot.threatLevel;
                maxThreat = Math.max(maxThreat, snapshot.threatLevel);
            }
            
            double avgConnections = metrics.snapshots.isEmpty() ? 0 : (double) totalConnections / metrics.snapshots.size();
            double avgSuspicious = metrics.snapshots.isEmpty() ? 0 : (double) totalSuspicious / metrics.snapshots.size();
            double avgThreat = metrics.snapshots.isEmpty() ? 0 : (double) totalThreat / metrics.snapshots.size();
            
            writer.write("Summary Statistics\n");
            writer.write("Average Connection Count," + String.format("%.2f", avgConnections) + "\n");
            writer.write("Maximum Connection Count," + maxConnections + "\n");
            writer.write("Average Suspicious Count," + String.format("%.2f", avgSuspicious) + "\n");
            writer.write("Maximum Suspicious Count," + maxSuspicious + "\n");
            writer.write("Average Threat Level," + String.format("%.2f", avgThreat) + "\n");
            writer.write("Maximum Threat Level," + maxThreat + "\n");
            writer.write("Total Attacks," + metrics.attacks.size() + "\n\n");
            
            writer.write("Hourly Activity\n");
            writer.write("Hour,Connection Count,Suspicious Count,Threat Level\n");
            
            Map<Integer, List<SecuritySnapshot>> hourlySnapshots = new TreeMap<>();
            
            for (SecuritySnapshot snapshot : metrics.snapshots) {
                String[] timestampParts = snapshot.timestamp.split(" ");
                if (timestampParts.length < 2) continue;
                
                String time = timestampParts[1];
                String[] timeParts = time.split(":");
                if (timeParts.length < 1) continue;
                
                int hour = Integer.parseInt(timeParts[0]);
                hourlySnapshots.computeIfAbsent(hour, k -> new ArrayList<>()).add(snapshot);
            }
            
            for (int hour = 0; hour < 24; hour++) {
                List<SecuritySnapshot> snapshots = hourlySnapshots.getOrDefault(hour, new ArrayList<>());
                
                int hourTotalConnections = 0;
                int hourTotalSuspicious = 0;
                int hourTotalThreat = 0;
                
                for (SecuritySnapshot snapshot : snapshots) {
                    hourTotalConnections += snapshot.connectionCount;
                    hourTotalSuspicious += snapshot.suspiciousCount;
                    hourTotalThreat += snapshot.threatLevel;
                }
                
                double hourAvgConnections = snapshots.isEmpty() ? 0 : (double) hourTotalConnections / snapshots.size();
                double hourAvgSuspicious = snapshots.isEmpty() ? 0 : (double) hourTotalSuspicious / snapshots.size();
                double hourAvgThreat = snapshots.isEmpty() ? 0 : (double) hourTotalThreat / snapshots.size();
                
                writer.write(
                    hour + "," +
                    String.format("%.2f", hourAvgConnections) + "," +
                    String.format("%.2f", hourAvgSuspicious) + "," +
                    String.format("%.2f", hourAvgThreat) + "\n"
                );
            }
            
            writer.write("\nAttacks by Type\n");
            writer.write("Attack Type,Count\n");
            
            Map<AttackType, Integer> attackTypeCounts = new EnumMap<>(AttackType.class);
            
            for (AttackRecord attack : metrics.attacks) {
                attackTypeCounts.put(attack.attackType, attackTypeCounts.getOrDefault(attack.attackType, 0) + 1);
            }
            
            for (Map.Entry<AttackType, Integer> entry : attackTypeCounts.entrySet()) {
                writer.write(entry.getKey().getName() + "," + entry.getValue() + "\n");
            }
            
            writer.write("\nAttacks by Alert Level\n");
            writer.write("Alert Level,Count\n");
            
            Map<AlertLevel, Integer> alertLevelCounts = new EnumMap<>(AlertLevel.class);
            
            for (AttackRecord attack : metrics.attacks) {
                alertLevelCounts.put(attack.alertLevel, alertLevelCounts.getOrDefault(attack.alertLevel, 0) + 1);
            }
            
            for (Map.Entry<AlertLevel, Integer> entry : alertLevelCounts.entrySet()) {
                writer.write(entry.getKey().name() + "," + entry.getValue() + "\n");
            }
            
            writer.write("\nTop Attack Sources\n");
            writer.write("IP Address,Attack Count\n");
            
            Map<String, Integer> attackSourceCounts = new HashMap<>();
            
            for (AttackRecord attack : metrics.attacks) {
                attackSourceCounts.put(attack.sourceIp, attackSourceCounts.getOrDefault(attack.sourceIp, 0) + 1);
            }
            
            attackSourceCounts.entrySet().stream()
                .sorted(Map.Entry.<String, Integer>comparingByValue().reversed())
                .limit(10)
                .forEach(entry -> {
                    try {
                        writer.write(entry.getKey() + "," + entry.getValue() + "\n");
                    } catch (IOException e) {
                        logger.warning("Error writing to report file: " + e.getMessage());
                    }
                });
        }
    }
    
    private void generateReportJson(File file, DailyMetrics metrics, String title) throws IOException {
        try (FileWriter writer = new FileWriter(file)) {
            StringBuilder json = new StringBuilder();
            json.append("{\n");
            json.append("  \"title\": \"").append(title).append("\",\n");
            json.append("  \"date\": \"").append(metrics.date).append("\",\n");
            json.append("  \"generatedAt\": \"").append(LocalDateTime.now().format(DateTimeFormatter.ISO_LOCAL_DATE_TIME)).append("\",\n");
            
            int totalConnections = 0;
            int maxConnections = 0;
            int totalSuspicious = 0;
            int maxSuspicious = 0;
            int totalThreat = 0;
            int maxThreat = 0;
            
            for (SecuritySnapshot snapshot : metrics.snapshots) {
                totalConnections += snapshot.connectionCount;
                maxConnections = Math.max(maxConnections, snapshot.connectionCount);
                totalSuspicious += snapshot.suspiciousCount;
                maxSuspicious = Math.max(maxSuspicious, snapshot.suspiciousCount);
                totalThreat += snapshot.threatLevel;
                maxThreat = Math.max(maxThreat, snapshot.threatLevel);
            }
            
            double avgConnections = metrics.snapshots.isEmpty() ? 0 : (double) totalConnections / metrics.snapshots.size();
            double avgSuspicious = metrics.snapshots.isEmpty() ? 0 : (double) totalSuspicious / metrics.snapshots.size();
            double avgThreat = metrics.snapshots.isEmpty() ? 0 : (double) totalThreat / metrics.snapshots.size();
            
            json.append("  \"summary\": {\n");
            json.append("    \"avgConnectionCount\": ").append(String.format("%.2f", avgConnections)).append(",\n");
            json.append("    \"maxConnectionCount\": ").append(maxConnections).append(",\n");
            json.append("    \"avgSuspiciousCount\": ").append(String.format("%.2f", avgSuspicious)).append(",\n");
            json.append("    \"maxSuspiciousCount\": ").append(maxSuspicious).append(",\n");
            json.append("    \"avgThreatLevel\": ").append(String.format("%.2f", avgThreat)).append(",\n");
            json.append("    \"maxThreatLevel\": ").append(maxThreat).append(",\n");
            json.append("    \"totalAttacks\": ").append(metrics.attacks.size()).append("\n");
            json.append("  },\n");
            
            json.append("  \"hourlyActivity\": [\n");
            
            Map<Integer, List<SecuritySnapshot>> hourlySnapshots = new TreeMap<>();
            
            for (SecuritySnapshot snapshot : metrics.snapshots) {
                String[] timestampParts = snapshot.timestamp.split(" ");
                if (timestampParts.length < 2) continue;
                
                String time = timestampParts[1];
                String[] timeParts = time.split(":");
                if (timeParts.length < 1) continue;
                
                int hour = Integer.parseInt(timeParts[0]);
                hourlySnapshots.computeIfAbsent(hour, k -> new ArrayList<>()).add(snapshot);
            }
            
            for (int hour = 0; hour < 24; hour++) {
                List<SecuritySnapshot> snapshots = hourlySnapshots.getOrDefault(hour, new ArrayList<>());
                
                int hourTotalConnections = 0;
                int hourTotalSuspicious = 0;
                int hourTotalThreat = 0;
                
                for (SecuritySnapshot snapshot : snapshots) {
                    hourTotalConnections += snapshot.connectionCount;
                    hourTotalSuspicious += snapshot.suspiciousCount;
                    hourTotalThreat += snapshot.threatLevel;
                }
                
                double hourAvgConnections = snapshots.isEmpty() ? 0 : (double) hourTotalConnections / snapshots.size();
                double hourAvgSuspicious = snapshots.isEmpty() ? 0 : (double) hourTotalSuspicious / snapshots.size();
                double hourAvgThreat = snapshots.isEmpty() ? 0 : (double) hourTotalThreat / snapshots.size();
                
                json.append("    {\n");
                json.append("      \"hour\": ").append(hour).append(",\n");
                json.append("      \"avgConnectionCount\": ").append(String.format("%.2f", hourAvgConnections)).append(",\n");
                json.append("      \"avgSuspiciousCount\": ").append(String.format("%.2f", hourAvgSuspicious)).append(",\n");
                json.append("      \"avgThreatLevel\": ").append(String.format("%.2f", hourAvgThreat)).append("\n");
                json.append("    }").append(hour < 23 ? ",\n" : "\n");
            }
            
            json.append("  ],\n");
            
            Map<AttackType, Integer> attackTypeCounts = new EnumMap<>(AttackType.class);
            
            for (AttackRecord attack : metrics.attacks) {
                attackTypeCounts.put(attack.attackType, attackTypeCounts.getOrDefault(attack.attackType, 0) + 1);
            }
            
            json.append("  \"attacksByType\": [\n");
            
            int typeIndex = 0;
            for (Map.Entry<AttackType, Integer> entry : attackTypeCounts.entrySet()) {
                json.append("    {\n");
                json.append("      \"attackType\": \"").append(entry.getKey().getName()).append("\",\n");
                json.append("      \"count\": ").append(entry.getValue()).append("\n");
                json.append("    }").append(++typeIndex < attackTypeCounts.size() ? ",\n" : "\n");
            }
            
            json.append("  ],\n");
            
            Map<AlertLevel, Integer> alertLevelCounts = new EnumMap<>(AlertLevel.class);
            
            for (AttackRecord attack : metrics.attacks) {
                alertLevelCounts.put(attack.alertLevel, alertLevelCounts.getOrDefault(attack.alertLevel, 0) + 1);
            }
            
            json.append("  \"attacksByAlertLevel\": [\n");
            
            int levelIndex = 0;
            for (Map.Entry<AlertLevel, Integer> entry : alertLevelCounts.entrySet()) {
                json.append("    {\n");
                json.append("      \"alertLevel\": \"").append(entry.getKey().name()).append("\",\n");
                json.append("      \"count\": ").append(entry.getValue()).append("\n");
                json.append("    }").append(++levelIndex < alertLevelCounts.size() ? ",\n" : "\n");
            }
            
            json.append("  ],\n");
            
            Map<String, Integer> attackSourceCounts = new HashMap<>();
            
            for (AttackRecord attack : metrics.attacks) {
                attackSourceCounts.put(attack.sourceIp, attackSourceCounts.getOrDefault(attack.sourceIp, 0) + 1);
            }
            
            json.append("  \"topAttackSources\": [\n");
            
            List<Map.Entry<String, Integer>> topSources = attackSourceCounts.entrySet().stream()
                .sorted(Map.Entry.<String, Integer>comparingByValue().reversed())
                .limit(10)
                .toList();
            
            for (int i = 0; i < topSources.size(); i++) {
                Map.Entry<String, Integer> entry = topSources.get(i);
                json.append("    {\n");
                json.append("      \"ip\": \"").append(entry.getKey()).append("\",\n");
                json.append("      \"count\": ").append(entry.getValue()).append("\n");
                json.append("    }").append(i < topSources.size() - 1 ? ",\n" : "\n");
            }
            
            json.append("  ]\n");
            json.append("}\n");
            
            writer.write(json.toString());
        }
    }
    
    public String generateCustomReport(String startDateStr, String endDateStr) {
        try {
            LocalDate startDate = LocalDate.parse(startDateStr, dateFormat);
            LocalDate endDate = LocalDate.parse(endDateStr, dateFormat);
            
            if (endDate.isBefore(startDate)) {
                return "Error: End date cannot be before start date";
            }
            
            List<DailyMetrics> reportMetrics = new ArrayList<>();
            
            LocalDate currentDate = startDate;
            while (!currentDate.isAfter(endDate)) {
                String dateKey = currentDate.format(dateFormat);
                DailyMetrics metrics = dailyMetricsMap.get(dateKey);
                
                if (metrics != null) {
                    reportMetrics.add(metrics);
                }
                
                currentDate = currentDate.plusDays(1);
            }
            
            if (reportMetrics.isEmpty()) {
                return "No data available for the specified date range";
            }
            
            String reportName = "custom_report_" + startDateStr + "_to_" + endDateStr + "." + exportFormat;
            File reportFile = new File(reportsFolder, reportName);
            
            if (reportMetrics.size() == 1) {
                generateReport(reportFile, reportMetrics.get(0),
                    "Custom Security Report - " + startDateStr, startDateStr, endDateStr);
            } else {
                generateWeeklyReportFile(reportFile, reportMetrics,
                    "Custom Security Report - " + startDateStr + " to " + endDateStr);
            }
            
            recordReportInDatabase("custom", startDateStr, endDateStr, reportFile.getPath());
            
            return "Custom report generated: " + reportName;
        } catch (Exception e) {
            logger.warning("Failed to generate custom report: " + e.getMessage());
            return "Error generating report: " + e.getMessage();
        }
    }
    
    private void recordReportInDatabase(String type, String startDate, String endDate, String filePath) {
        if (!enableDatabase || database == null) return;
        
        try {
            PreparedStatement stmt = database.prepareStatement(
                "INSERT INTO reports (timestamp, report_type, start_date, end_date, file_path) " +
                "VALUES (?, ?, ?, ?, ?)");
            
            stmt.setString(1, reportDateFormat.format(new Date()));
            stmt.setString(2, type);
            stmt.setString(3, startDate);
            stmt.setString(4, endDate);
            stmt.setString(5, filePath);
            
            stmt.executeUpdate();
            stmt.close();
        } catch (SQLException e) {
            logger.warning("Failed to record report in database: " + e.getMessage());
        }
    }
    
    public List<Map<String, String>> getReportHistory() {
        List<Map<String, String>> reports = new ArrayList<>();
        
        if (!enableDatabase || database == null) {
            File[] reportFiles = reportsFolder.listFiles();
            
            if (reportFiles == null) return reports;
            
            for (File file : reportFiles) {
                if (!file.isFile()) continue;
                
                Map<String, String> report = new LinkedHashMap<>();
                report.put("fileName", file.getName());
                report.put("path", file.getPath());
                report.put("size", (file.length() / 1024) + " KB");
                report.put("date", new SimpleDateFormat("yyyy-MM-dd HH:mm:ss")
                    .format(new Date(file.lastModified())));
                
                reports.add(report);
            }
            
            return reports;
        }
        
        try {
            Statement stmt = database.createStatement();
            ResultSet rs = stmt.executeQuery(
                "SELECT * FROM reports ORDER BY timestamp DESC");
            
            while (rs.next()) {
                Map<String, String> report = new LinkedHashMap<>();
                report.put("id", rs.getString("id"));
                report.put("timestamp", rs.getString("timestamp"));
                report.put("type", rs.getString("report_type"));
                report.put("startDate", rs.getString("start_date"));
                report.put("endDate", rs.getString("end_date"));
                report.put("path", rs.getString("file_path"));
                
                File file = new File(rs.getString("file_path"));
                if (file.exists()) {
                    report.put("size", (file.length() / 1024) + " KB");
                } else {
                    report.put("size", "File not found");
                }
                
                reports.add(report);
            }
            
            rs.close();
            stmt.close();
        } catch (SQLException e) {
            logger.warning("Failed to get report history from database: " + e.getMessage());
        }
        
        return reports;
    }
    
    private void purgeOldData() {
        LocalDate cutoffDate = LocalDate.now().minusDays(dataRetentionDays);
        
        dailyMetricsMap.entrySet().removeIf(entry -> {
            try {
                LocalDate date = LocalDate.parse(entry.getKey(), dateFormat);
                return date.isBefore(cutoffDate);
            } catch (Exception e) {
                return false;
            }
        });
        
        File[] metricsFiles = metricsFolder.listFiles();
        if (metricsFiles != null) {
            for (File file : metricsFiles) {
                try {
                    String fileName = file.getName();
                    if (fileName.endsWith(".csv") || fileName.endsWith(".json")) {
                        String dateStr = fileName.split("\\.")[0];
                        LocalDate date = LocalDate.parse(dateStr, dateFormat);
                        
                        if (date.isBefore(cutoffDate)) {
                            Files.deleteIfExists(file.toPath());
                        }
                    }
                } catch (Exception e) {
                    logger.warning("Failed to process file during purge: " + file.getName());
                }
            }
        }
        
        if (enableDatabase && database != null) {
            try {
                String cutoffDateStr = cutoffDate.format(dateFormat) + " 00:00:00";
                
                PreparedStatement stmt = database.prepareStatement(
                    "DELETE FROM metrics WHERE timestamp < ?");
                stmt.setString(1, cutoffDateStr);
                int deletedRows = stmt.executeUpdate();
                stmt.close();
                
                stmt = database.prepareStatement(
                    "DELETE FROM attacks WHERE timestamp < ?");
                stmt.setString(1, cutoffDateStr);
                int deletedAttacks = stmt.executeUpdate();
                stmt.close();
                
                logger.info("Purged old data: " + deletedRows + " metric records and " + 
                           deletedAttacks + " attack records deleted");
            } catch (SQLException e) {
                logger.warning("Failed to purge old data from database: " + e.getMessage());
            }
        }
    }
    
    public Map<String, Object> generateAnalyticsData() {
        Map<String, Object> data = new LinkedHashMap<>();
        
        int totalConnections = 0;
        int maxConnections = 0;
        int totalAttacks = 0;
        int highSeverityAttacks = 0;
        
        LocalDate today = LocalDate.now();
        LocalDate sevenDaysAgo = today.minusDays(7);
        
        data.put("currentThreatLevel", attackDetector.getCurrentThreatLevel());
        data.put("currentAlertLevel", attackDetector.getSystemAlertLevel().name());
        data.put("activeAttackSources", attackDetector.getActiveAttackSourcesCount());
        
        List<Map<String, Object>> dailyData = new ArrayList<>();
        Map<AttackType, Integer> attackTypeData = new EnumMap<>(AttackType.class);
        
        for (int i = 0; i < 7; i++) {
            LocalDate date = today.minusDays(i);
            String dateKey = date.format(dateFormat);
            DailyMetrics metrics = dailyMetricsMap.get(dateKey);
            
            Map<String, Object> day = new LinkedHashMap<>();
            day.put("date", dateKey);
            
            if (metrics != null) {
                int dayTotalConnections = 0;
                int dayMaxConnections = 0;
                int dayMaxThreat = 0;
                
                for (SecuritySnapshot snapshot : metrics.snapshots) {
                    dayTotalConnections += snapshot.connectionCount;
                    dayMaxConnections = Math.max(dayMaxConnections, snapshot.connectionCount);
                    dayMaxThreat = Math.max(dayMaxThreat, snapshot.threatLevel);
                }
                
                double dayAvgConnections = metrics.snapshots.isEmpty() ? 0 : 
                    (double) dayTotalConnections / metrics.snapshots.size();
                
                totalConnections += dayTotalConnections;
                maxConnections = Math.max(maxConnections, dayMaxConnections);
                totalAttacks += metrics.attacks.size();
                
                day.put("avgConnections", String.format("%.1f", dayAvgConnections));
                day.put("maxConnections", dayMaxConnections);
                day.put("maxThreat", dayMaxThreat);
                day.put("attackCount", metrics.attacks.size());
                
                for (AttackRecord attack : metrics.attacks) {
                    attackTypeData.put(attack.attackType, 
                        attackTypeData.getOrDefault(attack.attackType, 0) + 1);
                    
                    if (attack.alertLevel.getLevel() >= AlertLevel.HIGH.getLevel()) {
                        highSeverityAttacks++;
                    }
                }
            } else {
                day.put("avgConnections", 0);
                day.put("maxConnections", 0);
                day.put("maxThreat", 0);
                day.put("attackCount", 0);
            }
            
            dailyData.add(day);
        }
        
        data.put("dailyData", dailyData);
        
        List<Map<String, Object>> attackTypes = new ArrayList<>();
        for (Map.Entry<AttackType, Integer> entry : attackTypeData.entrySet()) {
            Map<String, Object> type = new LinkedHashMap<>();
            type.put("type", entry.getKey().getName());
            type.put("count", entry.getValue());
            attackTypes.add(type);
        }
        
        data.put("attackTypes", attackTypes);
        data.put("totalConnections", totalConnections);
        data.put("maxConnections", maxConnections);
        data.put("totalAttacks", totalAttacks);
        data.put("highSeverityAttacks", highSeverityAttacks);
        
        return data;
    }
    
    private class DailyMetrics {
        private final String date;
        private final List<SecuritySnapshot> snapshots = new ArrayList<>();
        private final List<AttackRecord> attacks = new ArrayList<>();
        
        public DailyMetrics(String date) {
            this.date = date;
        }
        
        public void addSnapshot(SecuritySnapshot snapshot) {
            snapshots.add(snapshot);
        }
        
        public void addAttackRecord(AttackRecord record) {
            attacks.add(record);
        }
        
        public List<AttackRecord> getRecentAttacks() {
            return new ArrayList<>(attacks);
        }
    }
    
    private class SecuritySnapshot {
        private String timestamp;
        private int connectionCount;
        private int suspiciousCount;
        private int blacklistedCount;
        private int whitelistedCount;
        private int threatLevel;
        private AlertLevel alertLevel;
        private int maxConnectionsPerSecond;
    }
    
    private class AttackRecord {
        private String timestamp;
        private String sourceIp;
        private AttackType attackType;
        private int threatScore;
        private AlertLevel alertLevel;
    }
}