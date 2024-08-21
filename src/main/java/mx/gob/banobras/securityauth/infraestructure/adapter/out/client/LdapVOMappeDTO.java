package mx.gob.banobras.securityauth.infraestructure.adapter.out.client;

import mx.gob.banobras.securityauth.infraestructure.config.dto.LdapDTO;

public class LdapVOMappeDTO {
	
	
	public LdapDTO mapperVOtoDTO(LdapVO ldapVO) {
		
		LdapDTO ldapDTO = new LdapDTO();
		
		ldapDTO.setUsuario(ldapVO.getUsuario());
		ldapDTO.setPassword(ldapVO.getPassword());
		ldapDTO.setExpediente(ldapVO.getExpediente());
		ldapDTO.setCuentaControl(ldapVO.getCuentaControl());
		ldapDTO.setNombre(ldapVO.getNombre());
		ldapDTO.setPuesto(ldapVO.getPuesto());
		ldapDTO.setArea(ldapVO.getArea());
		ldapDTO.setExtension(ldapVO.getExtension());
		ldapDTO.setActivo(ldapVO.getActivo());
		ldapDTO.setEmailPrincipal(ldapVO.getEmailPrincipal());
		ldapDTO.setEmail(ldapVO.getEmail());
		ldapDTO.setGrupoAplicativoPerfil(ldapVO.getGrupoAplicativoPerfil());
		ldapDTO.setListaTotalGrupos(ldapVO.getListaTotalGrupos());
		ldapDTO.setDetalle(ldapVO.getDetalle());
		return ldapDTO;
	}

	
	
}
