package mx.gob.banobras.securityauth.common.util;

/**
 * CommonConstant.java:
 * 
 * Clase ENUM que contiene mensajes y variables de uso comun
 *  
 * @author Marcos Gonzalez
 * @version 1.0, 13/06/2024
 * @see documento "MAR - Marco Arquitectonico de Referencia"
 * @since JDK 17
 */
public enum ConstantsSecurityAuth {
	/** Constante para el mensaje de error 500 */
	MSG_ERROR_500 ("Error interno, comunicarse con el administrador del sistema."),
	/** Constante para el mensaje de error 500 */
	MSG_ERROR_503 ("Error interno, servicio no disponible."),
	/** Constante para el mensaje de credenciales incorrectas */
	MSG_CREDENTIALS_INVALID ("Credenciales incorrectas."),
	/** Constante para el mensaje de error no haya datos en credenciales */
	MSG_CREDENTIALS_EMPTY ("No hay datos en credenciales."),
	/** Constante para el mensaje de error usuario no existe en ldap */
	MSG_USER_NOT_FOUND ("Usuario no encontrado en LDAP."),
	/** Constante para el mensaje de servicio no esta disponible LDAP */
	MSG_NO_SERVICE_LDAP ("Servicio no disponible - LDAP"),
	/** Constante para el mensaje de servicio no esta disponible Tokenizer */
	MSG_NO_SERVICE_TOKENIZER ("Servicio no disponible - Tokenizer"),
	/** COnstante para validar el localhost IPV4 */
	LOCALHOST_IPV4 ("127.0.0.1"),
	/** COnstante para validar el localhost IPV6 */
	LOCALHOST_IPV6 ("0:0:0:0:0:0:0:1"),
	/** Constante para validar la cadena "unknown" */
	UNKNOWN ("unknown"),
	/** Constante para validar el header "X-Forwarded-For" */
	H_X_FORWARDED_FOR ("X-Forwarded-For"),
	/** Constante para validar el header "Proxy-Client-IP" */
	H_PROXY_CLIENT_IP ("Proxy-Client-IP"),
	/** Constante para validar el header "WL-Proxy-Client-IP" */
	H_WL_PROXY_CLIENT_IP ("WL-Proxy-Client-IP"),
	/** Constante para validar el caracter coma "," */
	COMMA (","),
	/** Constante para imprimir en log */
	BUSCA_POR ("Busca por:: "),
	/** Constante para imprimir en log */
	ILLEGAL_ARG_EXCEPTION ("llegalArgumentException"),
	/** Constante para imprimir en log */
	NULL_POINTER_EXCEPTION ( "NullPointerException"),
	/** Constante para imprimir en log */
	EXCEPTION ("Exception"),
	/** Constante para imprimir en log */
	COMMUNICATION_EXCEPTION_LDAP ("CommunicationException - No hay conexion a LDAP"),
	/** Constante SSL */
	SSL ("SSL"),
	/** Constante HTTPS */
	HTTPS ("HTTPS"),
	/** Constante member  of */
	MEMBER_OF("memberOf"),
	/** Constante transaction_id */
	TRANSACTION_ID("transaction_id"),
	
	;
	
	private String name;

	private ConstantsSecurityAuth(String name) {
		this.name = name;
	}

	/**
	 * @return the name
	 */
	public String getName() {
		return name;
	}
}
