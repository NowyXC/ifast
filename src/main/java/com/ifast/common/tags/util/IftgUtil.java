package com.ifast.common.tags.util;

import com.ifast.common.domain.DictDO;
import com.ifast.common.service.DictService;
import com.ifast.common.tags.vo.ValueVO;
import org.thymeleaf.IEngineConfiguration;
import org.thymeleaf.context.ITemplateContext;
import org.thymeleaf.model.IProcessableElementTag;
import org.thymeleaf.standard.expression.IStandardExpression;
import org.thymeleaf.standard.expression.IStandardExpressionParser;
import org.thymeleaf.standard.expression.StandardExpressions;

import java.util.*;

/**
 * IftgUtil 辅助工具类
 *
 * @author: zet
 * @date: 2018/8/23 22:46
 */
public class IftgUtil {
    private static final String KEY_ALL = "all";

    /**
     * 获取数据
     *
     * @param dictService 字典service对象
     * @param dicType     字典类型编码
     * @return
     */
    public static List<ValueVO> getValues(DictService dictService, String dicType) {
        return getValues(dictService, dicType, null);
    }

    /**
     * 获取数据
     *
     * @param dictService   字典service对象
     * @param dicType       字典类型编码
     * @param selectedValue 默认选中的值
     * @return
     */
    public static List<ValueVO> getValues(DictService dictService, String dicType, String[] selectedValue) {
        if (KEY_ALL.contains(dicType)) {
            return getListType(dictService, dicType, selectedValue);
        }

        Map<String, Object> map = new HashMap<>(16);
        map.put("type", dicType);
        List<DictDO> dictDOS = dictService.selectByMap(map);
        List<ValueVO> options = parseToValues(dictDOS, selectedValue);
        return options;
    }

    public static List<ValueVO> getListType(DictService dictService, String dicType, String[] selectedValue) {
        List<DictDO> dictDOS = dictService.listType();
        return parseListTypeToValues(dictDOS, selectedValue);
    }

    /**
     * 获取标签对应值
     * @param context     thymeleaf 上下文对象
     * @param element       当前节点对象
     * @param attributeName 属性名
     * @return 回显对象值
     */
    public static List<String> getDataValues(ITemplateContext context, IProcessableElementTag element, String attributeName) {
        IStandardExpression expression = getExpression(context, element, attributeName);
        List<String> resp = new ArrayList<>();
        if(expression == null) return resp;
        Object result = expression.execute(context);
        if (Objects.nonNull(result)
                && !(result instanceof String)) {
            resp = (List<String>) (result);
            return resp;
        } else {
            if(Objects.nonNull(result)){
                resp.add(result.toString());
            }
            return resp;
        }


    }

    /**
     * 获取option 的值
     * @param context     thymeleaf 上下文对象
     * @param element       当前节点对象
     * @param attributeName 属性名
     * @return 标签对象值
     */
    public static String getTargetAttributeValue(ITemplateContext context, IProcessableElementTag element, String attributeName) {
        IStandardExpression expression = getExpression(context, element, attributeName);
        if(expression == null) return "";
        Object result = expression.execute(context);
        return result == null ? "" : result.toString();

    }


    private static IStandardExpression getExpression(ITemplateContext context, IProcessableElementTag element, String attributeName){
        String attributeValue = element.getAttributeValue(attributeName);
        IEngineConfiguration configuration = context.getConfiguration();
        IStandardExpressionParser expressionParser = StandardExpressions.getExpressionParser(configuration);
        try {
            return expressionParser.parseExpression(context, attributeValue);
        } catch (Exception e) {
            return null;
        }
    }


    /**
     * 转换格式
     *
     * @param dictDOS 待转换的字典数据
     * @return 转换后的格式
     */
    private static List<ValueVO> parseToValues(List<DictDO> dictDOS, String[] selectedValue) {
        List<ValueVO> valueVos = new ArrayList<>();
        ValueVO valueVo = null;
        List<String> selecteds = Objects.nonNull(selectedValue) ? Arrays.asList(selectedValue) : null;

        for (DictDO dictDO : dictDOS) {
            valueVo = new ValueVO();
            valueVo.setName(dictDO.getName());
            valueVo.setVlaue(dictDO.getValue());
            if (Objects.nonNull(selecteds) &&
                    selecteds.contains(dictDO.getValue())) {
                valueVo.setSelected(true);
            }
            valueVos.add(valueVo);
        }
        return valueVos;
    }

    /**
     * 转换格式(字典大类字典)
     *
     * @param dictDOS 待转换的字典数据
     * @return 转换后的格式
     */
    private static List<ValueVO> parseListTypeToValues(List<DictDO> dictDOS, String[] selectedValue) {
        List<ValueVO> valueVos = new ArrayList<>();
        ValueVO valueVo = null;
        List<String> selecteds = Objects.nonNull(selectedValue) ? Arrays.asList(selectedValue) : null;

        for (DictDO dictDO : dictDOS) {
            valueVo = new ValueVO();
            valueVo.setName(dictDO.getDescription());
            valueVo.setVlaue(dictDO.getType());
            if (Objects.nonNull(selecteds) &&
                    selecteds.contains(dictDO.getType())) {
                valueVo.setSelected(true);
            }
            valueVos.add(valueVo);
        }
        return valueVos;
    }

}
