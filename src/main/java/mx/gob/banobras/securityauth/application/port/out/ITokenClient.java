package mx.gob.banobras.securityauth.application.port.out;

/**
 * ITokenClientOutPort.java:
 * 
 * Interface de puerto de salida, para validar el token. 
 * 
 * @author Marcos Gonzalez
 * @version 1.0, 13/06/2024
 * @see documento "MAR - Marco Arquitectonico de Referencia"
 * @since JDK 17
 */
import java.io.IOException;
import java.net.http.HttpResponse;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;

import javax.naming.NamingException;

import mx.gob.banobras.securityauth.infraestructure.config.dto.SecurityAuthDTO;

public interface ITokenClient {
	
	/**
	 * Metodo para validar el token.
	 * 
	 * @param securityAuthDTO componente que conciten los datos del token.
	 * @return HttpResponse<String> objeto que contiene los datos de validacion del token. 
	 * 
	 * @throws NamingException Excepción durante el proces.
	 */
	public HttpResponse<String> getTokenAuthorization(SecurityAuthDTO securityAuthDTO) throws IOException, InterruptedException, NoSuchAlgorithmException, KeyManagementException;
	
	
	
}
