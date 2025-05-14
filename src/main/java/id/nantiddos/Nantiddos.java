package id.nantiddos;

import java.util.logging.Logger;
import org.bukkit.plugin.java.JavaPlugin;

/*
 * nantiddos java plugin
 */
public class Nantiddos extends JavaPlugin
{
  private static final Logger LOGGER=Logger.getLogger("nantiddos");

  public void onEnable()
  {
    LOGGER.info("nantiddos enabled");
  }

  public void onDisable()
  {
    LOGGER.info("nantiddos disabled");
  }
}
