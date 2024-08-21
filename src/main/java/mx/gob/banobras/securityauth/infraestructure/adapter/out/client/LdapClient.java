package mx.gob.banobras.securityauth.infraestructure.adapter.out.client;

/**
 * LdapClient.java:
 * 
 * Clase para conectarse en al directorio activo y validar el usuario y password. 
 *  
 * @author Marcos Gonzalez
 * @version 1.0, 13/06/2024
 * @see documento "MAR - Marco Arquitectonico de Referencia"
 * @since JDK 17
 */

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Hashtable;
import java.util.List;
import java.util.Map;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attributes;
import javax.naming.directory.InitialDirContext;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import mx.gob.banobras.securityauth.application.port.out.ILdapClient;
import mx.gob.banobras.securityauth.common.util.CipherAESCommon;
import mx.gob.banobras.securityauth.common.util.ConstantsSecurityAuth;
import mx.gob.banobras.securityauth.infraestructure.config.dto.SecurityAuthDTO;

@Component
public class LdapClient implements ILdapClient {

	/** Variable para las trazas de la clase */
	Logger log = LogManager.getLogger(LdapClient.class);

	/** Variable que contiene la url del ldap */
	@Value("${app.ldap.server}")
	String ldapServer;

	/** Variable que contiene el filtro para la busqueda en ldap */
	@Value("${app.ldap.search.base}")
	String ldapSearchBase;

	/** Variable que contiene el nombre de usuario de conexion en ldap */
	@Value("${app.ldap.username}")
	String ldapUsername;

	/** Variable que contiene el password de conexión de ldap */
	@Value("${app.ldap.password}")
	String ldapPassword;
	
	/** Variable que contiene el dominio de mail*/
	@Value("${app.ldap.dominio.mail}")
	String ldapDominioMail;

	/** Variable que contiene el valor para buscar en ldap */
	@Value("${app.ldap.validate}")
	boolean ldapValidate;

	private final CipherAESCommon cipherAESCommon;

	public LdapClient(CipherAESCommon cipherAESCommon) {
		this.cipherAESCommon = cipherAESCommon;
	}

	/**
	 * Metodo para buscar el usuario en LDAP.
	 * 
	 * @param userName - Alias del usuario.
	 * 
	 * @return regresa un valor booleano, si el valor es verdadero si encotro al
	 *         usario.
	 * @throws NamingException
	 * @throws BadPaddingException
	 * @throws IllegalBlockSizeException
	 * @throws InvalidAlgorithmParameterException
	 * @throws NoSuchPaddingException
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeyException
	 * 
	 */

	@Override
	public LdapVO autentication(SecurityAuthDTO securityAuthDTO)
			throws NamingException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException,
			InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
		/** Objeto para guardar los datos que provienen de LDAP */
		LdapVO dataLdapVO = null;
		String userName = null;

		/** Condicion para validar en LDAP */
		if(ldapValidate) {
			log.info("Se valida usuario en LDAP");
			log.info("La validacion es por usuario en credentials.");
			userName = securityAuthDTO.getUserName();

			// Valida solo el usuario
			InitialDirContext ctx = conexionLdap(false, securityAuthDTO);
			dataLdapVO = buscaUsuario(ctx, securityAuthDTO);
			if (dataLdapVO != null) {

				log.info(new StringBuilder().append("Si existe el usuario en LDAP: ").append(userName));
				if (securityAuthDTO.isValidUserPwd()) {
					try {
						/** valida el usuario y el password */
						InitialDirContext ctx2 = conexionLdap(securityAuthDTO.isValidUserPwd(), securityAuthDTO);
						dataLdapVO = buscaUsuario(ctx2, securityAuthDTO);

					} catch (Exception ee) {
						throw new NamingException("El password no existe o es iválido.");
					}
				}

			} else {
				log.info(new StringBuilder().append("No existe el usuario en LDAP."));
			}
		}else {
			dataLdapVO =  new LdapVO("usuario01","*****","10001","20002","usuario01 prueba",
					"Experto Técnico", "Area Prueba", "1530", 1, "usuario01@banobras.gob.mx", "Usuario01Prueba@banobras.gob.mx",
					null, null, null);
		}
		return dataLdapVO;
	}

	private String cleanText(Attributes attrs, String etiqueta) {
		String cadenaResult = "etiqueta";
		try {
			cadenaResult = attrs.get(etiqueta).toString();
			cadenaResult = cadenaResult.replace(etiqueta, "");
			cadenaResult = cadenaResult.replace(":", "");
		} catch (Exception exx) {
			cadenaResult = etiqueta;
		}
		return cadenaResult.trim();
	}

	private Integer findDisabled(SearchResult match, String etiqueta) {
		String cadena = match.toString();
		if (cadena.contains(etiqueta)) {
			return 0;
		} else {
			return 1;
		}
	}

	private List<String> findGroupsApp(String attr, String app) {
		String[] memberOfList = attr.split("DC=mx,");
		List<String> listGroup = new ArrayList<>();
		Map<String, Object> gruposMap = new HashMap<>();
		if (app.length() > 0) {

			for (String grupo : memberOfList) {
				if (grupo.contains(app)) {
					int ii = grupo.indexOf("CN=");
					String grupoAux = grupo.substring(ii + 3);
					int fi = grupoAux.indexOf(",");
					String valGrupo = grupoAux.substring(0, fi);

					if (!gruposMap.containsValue(valGrupo)) {
						listGroup.add(valGrupo);
						gruposMap.put(valGrupo, valGrupo);
					}
				}
			}
		}
		return listGroup;
	}

	private List<String> findGroupsAll(String attr) {
		String[] memberOfList = attr.split("DC=mx,");
		List<String> listGroup = new ArrayList<>();
		Map<String, Object> gruposMap = new HashMap<>();

		for (String grupo : memberOfList) {
			int ii = grupo.indexOf("CN=");
			String grupoAux = grupo.substring(ii + 3);
			int fi = grupoAux.indexOf(",");
			String valGrupo = grupoAux.substring(0, fi);

			if (!gruposMap.containsValue(valGrupo)) {
				listGroup.add(valGrupo);
				gruposMap.put(valGrupo, valGrupo);
			}
		}
		return listGroup;
	}

	private InitialDirContext conexionLdap(boolean findUserPwd, SecurityAuthDTO securityAuthDTO)
			throws NamingException {
		InitialDirContext ctx = null;
		Hashtable<String, String> env = new Hashtable<>();
		env.put(Context.SECURITY_AUTHENTICATION, "simple");
		env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
		env.put(Context.PROVIDER_URL, ldapServer);
		if (findUserPwd) {
			env.put(Context.SECURITY_PRINCIPAL, securityAuthDTO.getUserName() + ldapDominioMail);
			env.put(Context.SECURITY_CREDENTIALS, securityAuthDTO.getPassword());
			ctx = new InitialDirContext(env);
		} else {
			env.put(Context.SECURITY_PRINCIPAL, ldapUsername);
			env.put(Context.SECURITY_CREDENTIALS, ldapPassword);
			ctx = new InitialDirContext(env);
		}

		return ctx;
	}

	private LdapVO buscaUsuario(InitialDirContext ctx, SecurityAuthDTO securityAuthDTO)
			throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException,
			InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, NamingException {

		List<String> listaGrupoApp = null;
		List<String> listaGrupoAll = null;
		LdapVO dataLdapVO = null;

		/** Busca un usuario en especifico */
		String searchFilter = "(samaccountName=" + securityAuthDTO.getUserName() + ")";
		/** crea los filtros a buscar en LDAP */
		String[] reqAtt = { "uid", "cn", "sn", "initials", "displayname", "mail", "department", "company",
				"sAMAccountName", "userPrincipalName", "title", "mailNickname", "telephoneNumber", "userAccountControl",
				ConstantsSecurityAuth.MEMBER_OF.getName() };
		SearchControls controls = new SearchControls();
		controls.setSearchScope(SearchControls.SUBTREE_SCOPE);
		controls.setReturningAttributes(reqAtt);
		NamingEnumeration<SearchResult> objs = ctx.search(ldapSearchBase, searchFilter, controls);

		if (objs.hasMoreElements()) {

			while (objs.hasMoreElements()) {
				SearchResult match = objs.nextElement();
				Attributes attrs = match.getAttributes();

				try {
					listaGrupoApp = findGroupsApp(attrs.get("memberOf").toString(), securityAuthDTO.getAppName());
					/** Variable para revisar todos los atributos que regresa LDAP */
					listaGrupoAll = findGroupsAll(attrs.get("memberOf").toString());
				} catch (Exception exnull) {
					listaGrupoAll = null;
				}

				dataLdapVO = new LdapVO(cleanText(attrs, "sAMAccountName"),
						securityAuthDTO.isValidUserPwd()
								? cipherAESCommon.encryptStirngToAesHex(securityAuthDTO.getPassword())
								: null,
						cleanText(attrs, "initials"), cleanText(attrs, "userAccountControl"), cleanText(attrs, "cn"),
						cleanText(attrs, "title"), cleanText(attrs, "department"), cleanText(attrs, "telephoneNumber"),
						findDisabled(match, "Disabled Accounts"), cleanText(attrs, "userPrincipalName"),
						cleanText(attrs, "mail"), listaGrupoApp, listaGrupoAll, null);
				// attrs.toString());

			}

		}
		return dataLdapVO;
	}

}
