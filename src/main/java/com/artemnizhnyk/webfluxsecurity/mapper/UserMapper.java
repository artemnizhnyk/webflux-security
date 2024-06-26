package com.artemnizhnyk.webfluxsecurity.mapper;

import com.artemnizhnyk.webfluxsecurity.dto.UserDto;
import com.artemnizhnyk.webfluxsecurity.entity.UserEntity;
import org.mapstruct.InheritInverseConfiguration;
import org.mapstruct.Mapper;

@Mapper(componentModel = "spring")
public interface UserMapper {
    UserDto map(UserEntity userEntity);
    @InheritInverseConfiguration
    UserEntity map(UserDto userDto);
}
