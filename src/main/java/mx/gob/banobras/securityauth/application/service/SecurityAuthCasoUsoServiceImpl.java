package mx.gob.banobras.securityauth.application.service;

/**
 * TokenizerUseCaseService.java:
 * 
 * Clase de tipo @Service que contiene las funciones del caso de uso del Api TOkenizer
 *  
 * @author Marcos Gonzalez
 * @version 1.0, 13/06/2024
 * @see documento "MAR - Marco Arquitectonico de Referencia"
 * @since JDK 17
 */

import java.io.IOException;
import java.net.http.HttpResponse;
import java.util.Date;
import javax.naming.CommunicationException;
import javax.naming.NamingException;

import org.apache.commons.lang3.exception.ExceptionUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;

import com.google.gson.Gson;

import mx.gob.banobras.securityauth.application.port.in.ISecurityAuthCasoUsoService;
import mx.gob.banobras.securityauth.application.port.out.ILdapClient;
import mx.gob.banobras.securityauth.application.port.out.ITokenClient;
import mx.gob.banobras.securityauth.common.util.CipherAESCommon;
import mx.gob.banobras.securityauth.common.util.ConstantsSecurityAuth;
import mx.gob.banobras.securityauth.infraestructure.adapter.out.client.LdapVO;
import mx.gob.banobras.securityauth.infraestructure.adapter.out.client.LdapVOMappeDTO;
import mx.gob.banobras.securityauth.infraestructure.config.dto.CipherResponseDTO;
import mx.gob.banobras.securityauth.infraestructure.config.dto.DataDTO;
import mx.gob.banobras.securityauth.infraestructure.config.dto.ErrorMessageDTO;
import mx.gob.banobras.securityauth.infraestructure.config.dto.LdapDTO;
import mx.gob.banobras.securityauth.infraestructure.config.dto.LdapResponseDTO;
import mx.gob.banobras.securityauth.infraestructure.config.dto.SecurityAuthDTO;
import mx.gob.banobras.securityauth.infraestructure.config.dto.TokenizerResponseDTO;

@Service
public class SecurityAuthCasoUsoServiceImpl implements ISecurityAuthCasoUsoService {

	/** Trazas de la aplicación */
	Logger log = LogManager.getLogger(SecurityAuthCasoUsoServiceImpl.class);

	/** Variable para inejctar la clase Tokenizer */
	private final ITokenClient iTokenClient;
	/** Variable para inejctar la clase ILdapOutPort, para conexión a LDAP */
	private final ILdapClient iLdapClient;
	/** Injection variable para la clase CipherAESCommon */
	private final CipherAESCommon cipherAESCommon;

	/** Variable que contiene la url del ldap */
	@Value("${app.ldap.server}")
	String ldapServer;

	/**
	 * Constructor para inyectar los objetos Tokenizer, ILdapOutPort y
	 * CipherAESCommon
	 * 
	 * @param tokenizer       Objeto de dominio el Api Tokenizer.
	 * @param iLdapOutPort    Interface de puerto de salida para conectarse al LDAP.
	 * @param CipherAESCommon componente para desencriptar datos.
	 * 
	 */
	public SecurityAuthCasoUsoServiceImpl(ILdapClient iLdapClient, ITokenClient iTokenClient,
			CipherAESCommon cipherAESCommon) {
		this.iLdapClient = iLdapClient;
		this.iTokenClient = iTokenClient;
		this.cipherAESCommon = cipherAESCommon;
	}

	/**
	 * Metodo para validar el Token y autenticar el usuario.
	 * 
	 * @param securityAuthDTO Objeto que contien los datos para la validación y
	 *                        autenticacion.
	 * @return LdapResponseDTO objeto que contiene los datos del usuario en LDAP.
	 * 
	 */
	@Override
	public LdapResponseDTO authenticationTokenLdap(SecurityAuthDTO securityAuthDTO) {

		/** Variable que contiene el objeto de respuesta del token */
		LdapResponseDTO ldapResponseDTO = null;
		LdapVO ldapVO = null;

		HttpResponse<String> responseToken = null;

		try {
			if (securityAuthDTO.getCredentials().isEmpty()) {
				throw new IllegalArgumentException(ConstantsSecurityAuth.MSG_CREDENTIALS_EMPTY.getName());
			}
			/** Descripta las credenciales */
			securityAuthDTO = cipherAESCommon.getDataCredentials(securityAuthDTO);

			log.info("Valida el token");
			responseToken = iTokenClient.getTokenAuthorization(securityAuthDTO);
			if (responseToken.statusCode() == 200) {
				log.info(new StringBuilder().append("Valida si existe el usuario en LDAP: ")
						.append(securityAuthDTO.getUserName()));
				ldapVO = iLdapClient.autentication(securityAuthDTO);
				if (ldapVO != null) {
					LdapVOMappeDTO mapperLdapDTO = new LdapVOMappeDTO();
					LdapDTO ldapDTO = mapperLdapDTO.mapperVOtoDTO(ldapVO);
					ldapResponseDTO = new LdapResponseDTO();
					ldapResponseDTO.setStatusCode(HttpStatus.OK.value());
					ldapResponseDTO.setLdapDTO(ldapDTO);
				}
			} else {
				if (responseToken.statusCode() == 404) {
					log.info("URL token no encontrada.");
					ldapResponseDTO = new LdapResponseDTO();
					ErrorMessageDTO errorMessageDTO = new ErrorMessageDTO();
					errorMessageDTO.setMessage("URL no exsite");
					errorMessageDTO.setStatusCode(responseToken.statusCode());
					errorMessageDTO.setTimestamp(new Date());
					ldapResponseDTO.setErrorMessageDTO(errorMessageDTO);
					ldapResponseDTO.setStatusCode(responseToken.statusCode());

				} else {
					log.info("Token incorrecto");
					Gson gson = new Gson();
					TokenizerResponseDTO tokenizerResponseDTO = gson.fromJson(responseToken.body(),
							TokenizerResponseDTO.class);
					log.info(tokenizerResponseDTO.getStatusCode());
					log.info(tokenizerResponseDTO.getErrorMessageDTO().getMessage());
					ldapResponseDTO = new LdapResponseDTO();
					ErrorMessageDTO errorMessageDTO = new ErrorMessageDTO();
					errorMessageDTO.setMessage(tokenizerResponseDTO.getErrorMessageDTO().getMessage());
					errorMessageDTO.setStatusCode(tokenizerResponseDTO.getErrorMessageDTO().getStatusCode());
					errorMessageDTO.setTimestamp(tokenizerResponseDTO.getErrorMessageDTO().getTimestamp());
					ldapResponseDTO.setErrorMessageDTO(errorMessageDTO);
					ldapResponseDTO.setStatusCode(tokenizerResponseDTO.getStatusCode());
				}
			}

		} catch (IOException | InterruptedException ioex) {
			log.error("IOException | InterruptedException");
			log.error(ConstantsSecurityAuth.MSG_NO_SERVICE_TOKENIZER.getName(), ioex);
			ErrorMessageDTO message = new ErrorMessageDTO(HttpStatus.SERVICE_UNAVAILABLE.value(), new Date(),
					ConstantsSecurityAuth.MSG_NO_SERVICE_TOKENIZER.getName() + " - " + ldapServer);
			ldapResponseDTO = new LdapResponseDTO();
			ldapResponseDTO.setStatusCode(HttpStatus.SERVICE_UNAVAILABLE.value());
			ldapResponseDTO.setErrorMessageDTO(message);
			Thread.currentThread().interrupt();
		} catch (CommunicationException ex0) {
			log.error(ConstantsSecurityAuth.COMMUNICATION_EXCEPTION_LDAP.getName());
			log.error(ConstantsSecurityAuth.MSG_NO_SERVICE_LDAP.getName(), ex0);
			ErrorMessageDTO message = new ErrorMessageDTO(HttpStatus.SERVICE_UNAVAILABLE.value(), new Date(),
					ConstantsSecurityAuth.MSG_NO_SERVICE_LDAP.getName());
			ldapResponseDTO = new LdapResponseDTO();
			ldapResponseDTO.setStatusCode(HttpStatus.SERVICE_UNAVAILABLE.value());
			ldapResponseDTO.setErrorMessageDTO(message);
		} catch (IllegalArgumentException eil) {
			log.error(ConstantsSecurityAuth.ILLEGAL_ARG_EXCEPTION.getName(), eil);
			ErrorMessageDTO errorMessage = new ErrorMessageDTO(HttpStatus.INTERNAL_SERVER_ERROR.value(), new Date(),
					eil.getMessage());
			ldapResponseDTO = new LdapResponseDTO();
			ldapResponseDTO.setStatusCode(HttpStatus.INTERNAL_SERVER_ERROR.value());
			ldapResponseDTO.setErrorMessageDTO(errorMessage);

		} catch (Exception ex1) {
			log.error(ConstantsSecurityAuth.EXCEPTION.getName(), ex1);
			ErrorMessageDTO message = new ErrorMessageDTO(HttpStatus.INTERNAL_SERVER_ERROR.value(), new Date(),
					ex1.getMessage());
			ldapResponseDTO = new LdapResponseDTO();
			ldapResponseDTO.setStatusCode(HttpStatus.INTERNAL_SERVER_ERROR.value());
			ldapResponseDTO.setErrorMessageDTO(message);
		}
		return ldapResponseDTO;
	}

	/**
	 * Metodo para autentifica el usuario en LDAP
	 * 
	 * @param tokenizerDTO Objeto que contien los datos para generar el toekn.
	 * @return TokenizerResponseDTO regresa el objeto TokenizerResponseDTO que
	 *         contiene los datos del toekn.
	 * 
	 */
	@Override
	public LdapResponseDTO authenticationLdap(SecurityAuthDTO securityAuthDTO) {

		/** Variable que contiene el objeto de respuesta de LDAP */
		LdapResponseDTO ldapResponseDTO = null;
		LdapVO ldapVO = null;

		try {
			if (securityAuthDTO.getCredentials().isEmpty()) {
				throw new IllegalArgumentException(ConstantsSecurityAuth.MSG_CREDENTIALS_EMPTY.getName());
			}
			/** Descripta las credenciales */
			securityAuthDTO = cipherAESCommon.getDataCredentials(securityAuthDTO);

			log.info(new StringBuilder().append("Valida si existe el usuario en LDAP: ")
					.append(securityAuthDTO.getUserName()));

			ldapVO = iLdapClient.autentication(securityAuthDTO);

			if (ldapVO != null) {
				LdapVOMappeDTO mapperLdapDTO = new LdapVOMappeDTO();
				LdapDTO ldapDTO = mapperLdapDTO.mapperVOtoDTO(ldapVO);
				ldapResponseDTO = new LdapResponseDTO();
				ldapResponseDTO.setStatusCode(HttpStatus.OK.value());
				ldapResponseDTO.setLdapDTO(ldapDTO);
			} else {

				ErrorMessageDTO errorMessageDTO = new ErrorMessageDTO(HttpStatus.FORBIDDEN.value(), new Date(),
						ConstantsSecurityAuth.MSG_USER_NOT_FOUND.getName());
				ldapResponseDTO = new LdapResponseDTO();
				ldapResponseDTO.setStatusCode(HttpStatus.FORBIDDEN.value());
				ldapResponseDTO.setLdapDTO(null);
				ldapResponseDTO.setErrorMessageDTO(errorMessageDTO);

			}

		} catch (NamingException ex0) {
			log.error(ConstantsSecurityAuth.COMMUNICATION_EXCEPTION_LDAP.getName());
			log.error(ConstantsSecurityAuth.MSG_NO_SERVICE_LDAP.getName(), ex0);
			/**
			 * ErrorMessageDTO message = new
			 * ErrorMessageDTO(HttpStatus.SERVICE_UNAVAILABLE.value(), new Date(),
			 * ConstantsSecAuth.MSG_NO_SERVICE_LDAP.getName() + " =>* " + ldapServer + " - "
			 * + ExceptionUtils.getStackTrace(ex0));
			 **/
			ErrorMessageDTO message = new ErrorMessageDTO(HttpStatus.FORBIDDEN.value(), new Date(), ex0.getMessage());
			ldapResponseDTO = new LdapResponseDTO();
			ldapResponseDTO.setStatusCode(HttpStatus.SERVICE_UNAVAILABLE.value());
			ldapResponseDTO.setErrorMessageDTO(message);
		} catch (IllegalArgumentException eil) {
			log.error(ConstantsSecurityAuth.ILLEGAL_ARG_EXCEPTION.getName(), eil);
			ErrorMessageDTO errorMessage = new ErrorMessageDTO(HttpStatus.INTERNAL_SERVER_ERROR.value(), new Date(),
					eil.getMessage() + " ** " + ldapServer + " - " + ExceptionUtils.getStackTrace(eil));
			ldapResponseDTO = new LdapResponseDTO();
			ldapResponseDTO.setStatusCode(HttpStatus.INTERNAL_SERVER_ERROR.value());
			ldapResponseDTO.setErrorMessageDTO(errorMessage);

		} catch (Exception ex1) {
			log.error(ConstantsSecurityAuth.EXCEPTION.getName(), ex1);
			ErrorMessageDTO message = new ErrorMessageDTO(HttpStatus.INTERNAL_SERVER_ERROR.value(), new Date(),
					ex1.getMessage() + " && " + ldapServer + " - " + ExceptionUtils.getStackTrace(ex1));
			ldapResponseDTO = new LdapResponseDTO();
			ldapResponseDTO.setStatusCode(HttpStatus.INTERNAL_SERVER_ERROR.value());
			ldapResponseDTO.setErrorMessageDTO(message);
		}
		return ldapResponseDTO;
	}

	/**
	 * Metodo para obtener encirptar una cedena.
	 * 
	 * @param securityAuthDTO - DTO que contien los datos para encirptar.
	 * @return regresa el objeto encirptado.
	 * @throws Exception Excepción durante el proceso.
	 */
	@Override
	public CipherResponseDTO encode(SecurityAuthDTO securityAuthDTO) {

		/** Variable que contiene el objeto de respuesta del token */
		CipherResponseDTO cipherResponseDTO = null;
		String data = null;
		log.info("Inicia encode service");
		try {
			if (securityAuthDTO.getCredentials().isEmpty()) {
				throw new IllegalArgumentException(ConstantsSecurityAuth.MSG_CREDENTIALS_EMPTY.getName());
			}

			log.info("Encriptar datos");
			data = cipherAESCommon.encryptStirngToAesHex(securityAuthDTO.getCredentials());
			cipherResponseDTO = new CipherResponseDTO();
			cipherResponseDTO.setDataDTO(new DataDTO(data.toUpperCase()));
			cipherResponseDTO.setStatusCode(HttpStatus.OK.value());

		} catch (IllegalArgumentException eil) {
			log.error(ConstantsSecurityAuth.ILLEGAL_ARG_EXCEPTION.getName(), eil);
			ErrorMessageDTO errorMessage = new ErrorMessageDTO(HttpStatus.INTERNAL_SERVER_ERROR.value(), new Date(),
					eil.getMessage());
			cipherResponseDTO = new CipherResponseDTO();
			cipherResponseDTO.setStatusCode(HttpStatus.INTERNAL_SERVER_ERROR.value());
			cipherResponseDTO.setErrorMessageDTO(errorMessage);

		} catch (Exception ex1) {
			log.error(ConstantsSecurityAuth.EXCEPTION.getName(), ex1);
			ErrorMessageDTO message = new ErrorMessageDTO(HttpStatus.INTERNAL_SERVER_ERROR.value(), new Date(),
					ex1.getMessage());
			cipherResponseDTO = new CipherResponseDTO();
			cipherResponseDTO.setStatusCode(HttpStatus.INTERNAL_SERVER_ERROR.value());
			cipherResponseDTO.setErrorMessageDTO(message);
		}
		log.info("Termina encode service");
		return cipherResponseDTO;
	}

	/**
	 * Metodo para obtener desencirptar una cedena.
	 * 
	 * @param securityAuthDTO - DTO que contien los datos para desencirptar.
	 * @return regresa el objeto desencirptado.
	 * @throws Exception Excepción durante el proceso.
	 */
	@Override
	public CipherResponseDTO decode(SecurityAuthDTO securityAuthDTO) {

		/** Variable que contiene el objeto de respuesta del token */
		CipherResponseDTO cipherResponseDTO = null;
		String data = null;
		log.info("Inicia decode service");
		try {
			if (securityAuthDTO.getCredentials().isEmpty()) {
				throw new IllegalArgumentException(ConstantsSecurityAuth.MSG_CREDENTIALS_EMPTY.getName());
			}

			log.info("Encriptar datos");
			data = cipherAESCommon.decryptAesHexToString(securityAuthDTO.getCredentials());
			cipherResponseDTO = new CipherResponseDTO();
			cipherResponseDTO.setDataDTO(new DataDTO(data));
			cipherResponseDTO.setStatusCode(HttpStatus.OK.value());

		} catch (IllegalArgumentException eil) {
			log.error(ConstantsSecurityAuth.ILLEGAL_ARG_EXCEPTION.getName(), eil);
			ErrorMessageDTO errorMessage = new ErrorMessageDTO(HttpStatus.INTERNAL_SERVER_ERROR.value(), new Date(),
					eil.getMessage());
			cipherResponseDTO = new CipherResponseDTO();
			cipherResponseDTO.setStatusCode(HttpStatus.INTERNAL_SERVER_ERROR.value());
			cipherResponseDTO.setErrorMessageDTO(errorMessage);

		} catch (Exception ex1) {
			log.error(ConstantsSecurityAuth.EXCEPTION.getName(), ex1);
			ErrorMessageDTO message = new ErrorMessageDTO(HttpStatus.INTERNAL_SERVER_ERROR.value(), new Date(),
					ex1.getMessage());
			cipherResponseDTO = new CipherResponseDTO();
			cipherResponseDTO.setStatusCode(HttpStatus.INTERNAL_SERVER_ERROR.value());
			cipherResponseDTO.setErrorMessageDTO(message);
		}
		log.info("Termina decode service");
		return cipherResponseDTO;
	}

}
