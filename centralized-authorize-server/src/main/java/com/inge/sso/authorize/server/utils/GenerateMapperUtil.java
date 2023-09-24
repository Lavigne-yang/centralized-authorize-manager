package com.inge.sso.authorize.server.utils;

import com.baomidou.mybatisplus.generator.FastAutoGenerator;
import com.baomidou.mybatisplus.generator.config.DataSourceConfig;
import com.baomidou.mybatisplus.generator.config.OutputFile;
import com.baomidou.mybatisplus.generator.engine.FreemarkerTemplateEngine;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/**
 * @author lavyoung1325
 */
public class GenerateMapperUtil {
    private static final DataSourceConfig.Builder DATA_SOURCE_CONFIG = new DataSourceConfig.Builder("jdbc:mysql://192.168.3.100:3306/cam?useUnicode=true&characterEncoding=utf-8&useSSL=false&serverTimezone=UTC", "root", "123456");

    public static void main(String[] args) {
        try {
            System.out.println("start...");
            FastAutoGenerator.create("jdbc:mysql://192.168.3.100:3306/cam?useUnicode=true&characterEncoding=utf-8&useSSL=false&serverTimezone=UTC", "root", "123456")
                    // 全局配置
                    .globalConfig((scanner, builder) -> builder.author(scanner.apply("lavyoung1325"))
                            .outputDir("F://tmp")
                    )
                    // 包配置
                    .packageConfig((scanner, builder) -> builder.parent(scanner.apply("com.inge.sso.authorize.server"))
                            .pathInfo(Collections.singletonMap(OutputFile.mapper, "F://tmp")))
                    // 策略配置
                    .strategyConfig((scanner, builder) -> builder.addInclude(getTables(scanner.apply("cam_user,cam_system_authority,cam_role_authority," +
                                    "cam_role,cam_user,role")))
                            .addTablePrefix("cam_")
                            .mapperBuilder().enableBaseResultMap().enableBaseColumnList().enableFileOverride()
                            .controllerBuilder().enableRestStyle()
                            .entityBuilder().enableLombok()
                            .build())
                    .templateEngine(new FreemarkerTemplateEngine())
                    .execute();
            System.out.println("end...");
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    protected static List<String> getTables(String tables) {
        return "all".equals(tables) ? Collections.emptyList() : Arrays.asList(tables.split(","));
    }
}
