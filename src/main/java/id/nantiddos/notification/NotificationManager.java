package id.nantiddos.notification;

import id.nantiddos.Nantiddos;
import id.nantiddos.protection.AttackDetector;
import id.nantiddos.protection.AttackDetector.AttackType;
import id.nantiddos.protection.AttackDetector.AlertLevel;

import java.awt.Color;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import java.util.logging.Logger;

import jakarta.mail.Message;
import jakarta.mail.MessagingException;
import jakarta.mail.PasswordAuthentication;
import jakarta.mail.Session;
import jakarta.mail.Transport;
import jakarta.mail.internet.InternetAddress;
import jakarta.mail.internet.MimeMessage;

import org.bukkit.Bukkit;
import org.bukkit.ChatColor;
import org.bukkit.configuration.ConfigurationSection;
import org.bukkit.entity.Player;
import org.bukkit.scheduler.BukkitTask;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;

public class NotificationManager {
    private final Nantiddos plugin;
    private final Logger logger;
    
    private boolean enabled;
    private boolean discordEnabled;
    private boolean emailEnabled;
    private String discordWebhookUrl;
    private String emailHost;
    private int emailPort;
    private String emailUsername;
    private String emailPassword;
    private String emailFrom;
    private String[] emailRecipients;
    private AlertLevel minNotificationLevel;
    private boolean notifyOnAttack;
    private boolean notifyOnBlacklist;
    private boolean notifyOnProtectionToggle;
    private boolean notifyOnConfigChange;
    private long rateLimitMillis;
    
    private final Map<NotificationType, Long> lastNotificationTimes = new ConcurrentHashMap<>();
    private final Map<String, Long> ipNotificationHistory = new ConcurrentHashMap<>();
    private final Set<String> notifiedIps = new HashSet<>();
    
    private BukkitTask cleanupTask;
    private final SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
    
    public enum NotificationType {
        ATTACK_DETECTED("Attack Detected", Color.RED),
        IP_BLACKLISTED("IP Blacklisted", Color.ORANGE),
        PROTECTION_TOGGLED("Protection Toggled", Color.YELLOW),
        CONFIG_CHANGED("Configuration Changed", Color.BLUE),
        SYSTEM_ALERT("System Alert", Color.MAGENTA);
        
        private final String title;
        private final Color color;
        
        NotificationType(String title, Color color) {
            this.title = title;
            this.color = color;
        }
        
        public String getTitle() {
            return title;
        }
        
        public Color getColor() {
            return color;
        }
        
        public int getColorValue() {
            return color.getRGB() & 0xFFFFFF;
        }
    }
    
    public NotificationManager(Nantiddos plugin) {
        this.plugin = plugin;
        this.logger = plugin.getLogger();
        
        loadConfig();
        startCleanupTask();
        
        logger.info("Notification system initialized");
    }
    
    public void loadConfig() {
        ConfigurationSection config = plugin.getConfig().getConfigurationSection("notifications");
        
        if (config == null) {
            logger.warning("No notification configuration found. Using defaults.");
            enabled = false;
            discordEnabled = false;
            emailEnabled = false;
            minNotificationLevel = AlertLevel.HIGH;
            notifyOnAttack = true;
            notifyOnBlacklist = true;
            notifyOnProtectionToggle = false;
            notifyOnConfigChange = false;
            rateLimitMillis = 60000; 
            return;
        }
        
        enabled = config.getBoolean("enabled", false);
        discordEnabled = config.getBoolean("discord.enabled", false);
        discordWebhookUrl = config.getString("discord.webhook-url", "");
        
        emailEnabled = config.getBoolean("email.enabled", false);
        emailHost = config.getString("email.host", "smtp.gmail.com");
        emailPort = config.getInt("email.port", 587);
        emailUsername = config.getString("email.username", "");
        emailPassword = config.getString("email.password", "");
        emailFrom = config.getString("email.from", "nantiddos@example.com");
        
        if (config.isList("email.recipients")) {
            emailRecipients = config.getStringList("email.recipients").toArray(new String[0]);
        } else {
            emailRecipients = new String[0];
        }
        
        String level = config.getString("min-level", "HIGH");
        try {
            minNotificationLevel = AlertLevel.valueOf(level.toUpperCase());
        } catch (IllegalArgumentException e) {
            minNotificationLevel = AlertLevel.HIGH;
        }
        
        notifyOnAttack = config.getBoolean("events.attack", true);
        notifyOnBlacklist = config.getBoolean("events.blacklist", true);
        notifyOnProtectionToggle = config.getBoolean("events.protection-toggle", false);
        notifyOnConfigChange = config.getBoolean("events.config-change", false);
        
        rateLimitMillis = config.getLong("rate-limit-seconds", 60) * 1000;
    }
    
    public void shutdown() {
        if (cleanupTask != null && !cleanupTask.isCancelled()) {
            cleanupTask.cancel();
        }
        
        notifiedIps.clear();
        ipNotificationHistory.clear();
        lastNotificationTimes.clear();
    }
    
    private void startCleanupTask() {
        cleanupTask = Bukkit.getScheduler().runTaskTimerAsynchronously(plugin, () -> {
            long now = System.currentTimeMillis();
            
            ipNotificationHistory.entrySet().removeIf(entry -> 
                now - entry.getValue() > TimeUnit.HOURS.toMillis(24));
                
        }, 20 * 60 * 30, 20 * 60 * 30); 
    }
    
    public void notifyAttack(AttackType attackType, Set<String> sourceIps, AlertLevel alertLevel) {
        if (!enabled || !notifyOnAttack || alertLevel.getLevel() < minNotificationLevel.getLevel()) {
            return;
        }
        
        if (isRateLimited(NotificationType.ATTACK_DETECTED)) {
            return;
        }
        
        String message = buildAttackMessage(attackType, sourceIps, alertLevel);
        
        if (discordEnabled) {
            sendDiscordNotification(NotificationType.ATTACK_DETECTED, "Attack Detected: " + attackType.getName(), 
                message, buildIpFields(sourceIps), alertLevel);
        }
        
        if (emailEnabled && alertLevel.getLevel() >= AlertLevel.HIGH.getLevel()) {
            sendEmailNotification("NantiDDoS - Attack Detected: " + attackType.getName(),
                message + "\n\nSource IPs:\n" + String.join("\n", sourceIps));
        }
        
        notifyAdmins("§c[NantiDDoS] §eAttack Detected: §c" + attackType.getName() + 
            " §e(Threat: " + alertLevel.getColor() + alertLevel.name() + "§e) from " + sourceIps.size() + " IPs");
        
        for (String ip : sourceIps) {
            ipNotificationHistory.put(ip, System.currentTimeMillis());
            notifiedIps.add(ip);
        }
    }
    
    public void notifyBlacklisted(String ip, String reason) {
        if (!enabled || !notifyOnBlacklist) {
            return;
        }
        
        if (isRateLimited(NotificationType.IP_BLACKLISTED)) {
            return;
        }
        
        String message = "IP " + ip + " has been blacklisted.\n" +
            "Reason: " + reason + "\n" +
            "Time: " + dateFormat.format(new Date());
        
        Map<String, String> fields = new HashMap<>();
        fields.put("IP Address", ip);
        fields.put("Reason", reason);
        fields.put("Time", dateFormat.format(new Date()));
        
        if (discordEnabled) {
            sendDiscordNotification(NotificationType.IP_BLACKLISTED, "IP Blacklisted", message, fields, AlertLevel.MEDIUM);
        }
        
        if (emailEnabled) {
            sendEmailNotification("NantiDDoS - IP Blacklisted", message);
        }
        
        notifyAdmins("§c[NantiDDoS] §eIP §c" + ip + " §ehas been blacklisted. Reason: §c" + reason);
        
        ipNotificationHistory.put(ip, System.currentTimeMillis());
        notifiedIps.add(ip);
    }
    
    public void notifyProtectionToggled(boolean enabled, String actor) {
        if (!this.enabled || !notifyOnProtectionToggle) {
            return;
        }
        
        if (isRateLimited(NotificationType.PROTECTION_TOGGLED)) {
            return;
        }
        
        String message = "Protection has been " + (enabled ? "enabled" : "disabled") + " by " + actor + ".\n" +
            "Time: " + dateFormat.format(new Date());
        
        Map<String, String> fields = new HashMap<>();
        fields.put("Status", enabled ? "Enabled" : "Disabled");
        fields.put("Actor", actor);
        fields.put("Time", dateFormat.format(new Date()));
        
        if (discordEnabled) {
            sendDiscordNotification(NotificationType.PROTECTION_TOGGLED, "Protection Status Changed", 
                message, fields, AlertLevel.LOW);
        }
        
        if (emailEnabled) {
            sendEmailNotification("NantiDDoS - Protection Status Changed", message);
        }
        
        notifyAdmins("§6[NantiDDoS] §eProtection has been " + 
            (enabled ? "§aenabled" : "§cdisabled") + " §eby §f" + actor);
    }
    
    public void notifyConfigChanged(String actor) {
        if (!enabled || !notifyOnConfigChange) {
            return;
        }
        
        if (isRateLimited(NotificationType.CONFIG_CHANGED)) {
            return;
        }
        
        String message = "Configuration has been changed by " + actor + ".\n" +
            "Time: " + dateFormat.format(new Date());
        
        Map<String, String> fields = new HashMap<>();
        fields.put("Actor", actor);
        fields.put("Time", dateFormat.format(new Date()));
        
        if (discordEnabled) {
            sendDiscordNotification(NotificationType.CONFIG_CHANGED, "Configuration Changed", 
                message, fields, AlertLevel.LOW);
        }
        
        if (emailEnabled) {
            sendEmailNotification("NantiDDoS - Configuration Changed", message);
        }
        
        notifyAdmins("§6[NantiDDoS] §eConfiguration has been changed by §f" + actor);
    }
    
    public void notifySystemAlert(String title, String message, AlertLevel alertLevel) {
        if (!enabled || alertLevel.getLevel() < minNotificationLevel.getLevel()) {
            return;
        }
        
        if (isRateLimited(NotificationType.SYSTEM_ALERT)) {
            return;
        }
        
        String fullMessage = message + "\n" +
            "Time: " + dateFormat.format(new Date());
        
        Map<String, String> fields = new HashMap<>();
        fields.put("Alert Level", alertLevel.name());
        fields.put("Time", dateFormat.format(new Date()));
        
        if (discordEnabled) {
            sendDiscordNotification(NotificationType.SYSTEM_ALERT, title, fullMessage, fields, alertLevel);
        }
        
        if (emailEnabled && alertLevel.getLevel() >= AlertLevel.HIGH.getLevel()) {
            sendEmailNotification("NantiDDoS - System Alert: " + title, fullMessage);
        }
        
        notifyAdmins("§c[NantiDDoS] §e" + title + ": " + alertLevel.getColor() + message);
    }
    
    private void sendDiscordNotification(NotificationType type, String title, String description, 
            Map<String, String> fields, AlertLevel alertLevel) {
        if (!discordEnabled || discordWebhookUrl == null || discordWebhookUrl.isEmpty()) {
            return;
        }
        
        Bukkit.getScheduler().runTaskAsynchronously(plugin, () -> {
            try {
                URL url = new URL(discordWebhookUrl);
                HttpURLConnection connection = (HttpURLConnection) url.openConnection();
                connection.setRequestMethod("POST");
                connection.setRequestProperty("Content-Type", "application/json");
                connection.setDoOutput(true);
                
                JSONObject json = new JSONObject();
                
                JSONObject embed = new JSONObject();
                embed.put("title", title);
                embed.put("description", description);
                embed.put("color", type.getColorValue());
                
                JSONArray embedFields = new JSONArray();
                
                for (Map.Entry<String, String> entry : fields.entrySet()) {
                    JSONObject field = new JSONObject();
                    field.put("name", entry.getKey());
                    field.put("value", entry.getValue());
                    field.put("inline", true);
                    embedFields.add(field);
                }
                
                embed.put("fields", embedFields);
                
                JSONObject footer = new JSONObject();
                footer.put("text", "NantiDDoS • " + dateFormat.format(new Date()));
                embed.put("footer", footer);
                
                JSONArray embeds = new JSONArray();
                embeds.add(embed);
                
                json.put("embeds", embeds);
                
                String jsonString = json.toJSONString();
                
                try (OutputStream os = connection.getOutputStream()) {
                    byte[] input = jsonString.getBytes(StandardCharsets.UTF_8);
                    os.write(input, 0, input.length);
                }
                
                int responseCode = connection.getResponseCode();
                
                if (responseCode != HttpURLConnection.HTTP_NO_CONTENT && responseCode != HttpURLConnection.HTTP_OK) {
                    logger.warning("Failed to send Discord notification. Response code: " + responseCode);
                }
                
                connection.disconnect();
                
            } catch (Exception e) {
                logger.warning("Failed to send Discord notification: " + e.getMessage());
            }
        });
    }
    
    private void sendEmailNotification(String subject, String content) {
        if (!emailEnabled || emailUsername == null || emailUsername.isEmpty() || 
            emailPassword == null || emailPassword.isEmpty() || 
            emailRecipients == null || emailRecipients.length == 0) {
            return;
        }
        
        Bukkit.getScheduler().runTaskAsynchronously(plugin, () -> {
            try {
                Properties props = new Properties();
                props.put("mail.smtp.auth", "true");
                props.put("mail.smtp.starttls.enable", "true");
                props.put("mail.smtp.host", emailHost);
                props.put("mail.smtp.port", emailPort);
                
                Session session = Session.getInstance(props, new jakarta.mail.Authenticator() {
                    protected PasswordAuthentication getPasswordAuthentication() {
                        return new PasswordAuthentication(emailUsername, emailPassword);
                    }
                });
                
                Message message = new MimeMessage(session);
                message.setFrom(new InternetAddress(emailFrom));
                
                for (String recipient : emailRecipients) {
                    message.addRecipient(Message.RecipientType.TO, new InternetAddress(recipient));
                }
                
                message.setSubject(subject);
                message.setText(content);
                
                Transport.send(message);
                
            } catch (MessagingException e) {
                logger.warning("Failed to send email notification: " + e.getMessage());
            }
        });
    }
    
    private boolean isRateLimited(NotificationType type) {
        long now = System.currentTimeMillis();
        Long lastTime = lastNotificationTimes.get(type);
        
        if (lastTime != null && now - lastTime < rateLimitMillis) {
            return true;
        }
        
        lastNotificationTimes.put(type, now);
        return false;
    }
    
    private boolean isIpRateLimited(String ip) {
        long now = System.currentTimeMillis();
        Long lastTime = ipNotificationHistory.get(ip);
        
        if (lastTime != null && now - lastTime < rateLimitMillis) {
            return true;
        }
        
        return false;
    }
    
    private String buildAttackMessage(AttackType attackType, Set<String> sourceIps, AlertLevel alertLevel) {
        StringBuilder sb = new StringBuilder();
        
        sb.append("Attack Type: ").append(attackType.getName()).append("\n");
        sb.append("Description: ").append(attackType.getDescription()).append("\n");
        sb.append("Alert Level: ").append(alertLevel.name()).append("\n");
        sb.append("Source IPs: ").append(sourceIps.size()).append("\n");
        sb.append("Time: ").append(dateFormat.format(new Date())).append("\n");
        
        return sb.toString();
    }
    
    private Map<String, String> buildIpFields(Set<String> ips) {
        Map<String, String> fields = new HashMap<>();
        
        fields.put("Number of IPs", String.valueOf(ips.size()));
        
        int count = 0;
        StringBuilder ipList = new StringBuilder();
        
        for (String ip : ips) {
            if (count < 10) {
                ipList.append(ip).append("\n");
                count++;
            } else {
                ipList.append("... and ").append(ips.size() - 10).append(" more");
                break;
            }
        }
        
        fields.put("IP Addresses", ipList.toString());
        
        return fields;
    }
    
    private void notifyAdmins(String message) {
        Bukkit.getScheduler().runTask(plugin, () -> {
            for (Player player : Bukkit.getOnlinePlayers()) {
                if (player.hasPermission("nantiddos.admin")) {
                    player.sendMessage(message);
                }
            }
            
            logger.info(ChatColor.stripColor(message));
        });
    }
    
    public boolean isEnabled() {
        return enabled;
    }
    
    public Set<String> getNotifiedIps() {
        return new HashSet<>(notifiedIps);
    }
    
    public int getNotificationCount() {
        return lastNotificationTimes.size();
    }
}