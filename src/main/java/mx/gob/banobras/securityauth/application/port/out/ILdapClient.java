package mx.gob.banobras.securityauth.application.port.out;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.naming.NamingException;

import mx.gob.banobras.securityauth.infraestructure.adapter.out.client.LdapVO;
import mx.gob.banobras.securityauth.infraestructure.config.dto.SecurityAuthDTO;

/**
 * ILdapOutPort.java:
 * 
 * Interface de puerto de salida, para buscar el usuario 
 * 
 * @author Marcos Gonzalez
 * @version 1.0, 13/06/2024
 * @see documento "MAR - Marco Arquitectonico de Referencia"
 * @since JDK 17
 */
public interface ILdapClient {

	/**
	 * Metodo para buscar el usuario.
	 * 
	 * @param securityAuthDTO componente que conciten el usuario a buscar.
	 * @return LdapVO objeto que contiene los datos de usario en LDAP. 
	 * 
	 * @throws NamingException Excepción durante el proces.
	 */
	public LdapVO autentication(SecurityAuthDTO securityAuthDTO) throws NamingException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException;
	
}
