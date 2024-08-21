package mx.gob.banobras.securityauth;
/**
 * BanobrasSecurityAuthApplication.java:
 * 
 * Clase principal para levantar la aplicacion de
 * de autenticacion.
 * 
 * @author Marcos Gonzalez
 * @version 1.0, 20/06/2024
 * @see documento "MAR - Marco Arquitectonico de Referencia"
 * @since JDK 17
 */

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.security.servlet.SecurityAutoConfiguration;

@SpringBootApplication(exclude = {SecurityAutoConfiguration.class })
public class SecurityAuthApp implements CommandLineRunner{
	
	/** Variable para imprimir los logs */
	private static final Log log = LogFactory.getLog(SecurityAuthApp.class);

	public static void main(String[] args) {
		SpringApplication.run(SecurityAuthApp.class, args);
	}

	/**
	 * Metodo para imprimir el inicio de Security Auhtenticator.
	 * 
	 * @param String[] - Parametros 
	 * 
	 */
	@Override
	public void run(String... args) throws Exception {
		/** Variable para imprimir la diagonal inversa "\" */
		final char dInv = 92;
		final String SPACES ="      "; 
		log.info(SPACES);
		log.info("            .   ______       _   __     __ _ _");
		log.info("           /" + dInv + dInv + " |  __  |__  _| |_| | __  " + dInv +" " + dInv + " " + dInv + " " + dInv);
		log.info("          ( ( )| |__| | | |_   _| |/  " + dInv +"  " + dInv +" " + dInv + " " + dInv + " " + dInv );
		log.info("           "+ dInv + dInv + "/ |  __  | |_| | | |  / " + dInv + " " + dInv + "  ) ) ) )");
		log.info("            '  | |  | |_____|_| |_|  |_| / / / /");
		log.info("           =============================/_/_/_/");
		log.info(SPACES);
		log.info("    _ _ __  ______                       _   _");
		log.info("   / / / / |  ____|____ ____ _   _ _____(_)_| |__    _");
		log.info("  / / / /  | |____|  __|  __| | | |  _  | |_   _ |  | |  .");
		log.info(" / / / /   |____  | |__| |  | | | | |_| | | | |" + dInv + " " + dInv + " / /  /"+ dInv + dInv );
		log.info("( ( ( (         | |  __| |  | | | |    _| | | | " + dInv + "   /  ( ( )");
		log.info(" " + dInv +" " + dInv + " " + dInv + " " + dInv + "    ____| | |__| |__| |_| | |" + dInv +" " + dInv + "| | | |  | |    "+ dInv + dInv + "/");
		log.info("  " + dInv +" " + dInv + " " + dInv + " " + dInv + "  |______|____|____|_____|_| " + dInv +"_" + dInv + "_| |_|  |_|     '");
		log.info("   " + dInv +"_" + dInv + "_" + dInv + "_" + dInv + "===================================================");
		log.info("        **                    Security Ahutenticator is online!");
		log.info("REST APP SYNC ::::");
	}
	
	
}
