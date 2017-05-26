package com.kumuluz.ee.security.processor;

import com.kumuluz.ee.security.annotations.Keycloak;

import javax.annotation.processing.*;
import javax.annotation.security.DeclareRoles;
import javax.annotation.security.DenyAll;
import javax.annotation.security.PermitAll;
import javax.annotation.security.RolesAllowed;
import javax.lang.model.SourceVersion;
import javax.lang.model.element.Element;
import javax.lang.model.element.ElementKind;
import javax.lang.model.element.TypeElement;
import javax.tools.FileObject;
import javax.tools.StandardLocation;
import java.io.IOException;
import java.io.Writer;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

/**
 * Compile-time annotation processor for DeclareRoles, RolesAllowed, PermitAll and DenyAll annotations. Generates service file.
 *
 * @author Benjamin Kastelic
 */
public class AnnotationProcessor extends AbstractProcessor {

    private Filer filer;

    // clases with @DeclareRoles annotation
    private Set<String> roleElementNames = new HashSet<>();

    // classes with @RolesAllowed, @PermitAll and @DenyAll annotations
    private Set<String> constraintElementNames = new HashSet<>();

    @Override
    public SourceVersion getSupportedSourceVersion() {
        return SourceVersion.latest();
    }

    @Override
    public Set<String> getSupportedAnnotationTypes() {
        return Collections.singleton("*");
    }

    @Override
    public synchronized void init(ProcessingEnvironment processingEnv) {
        super.init(processingEnv);
        filer = processingEnv.getFiler();
    }

    @Override
    public boolean process(Set<? extends TypeElement> annotations, RoundEnvironment roundEnvironment) {
        Set<? extends Element> elements = roundEnvironment.getElementsAnnotatedWith(Keycloak.class);
        elements.forEach(element -> extractElementName(roleElementNames, element));

        elements = roundEnvironment.getElementsAnnotatedWith(DeclareRoles.class);
        elements.forEach(element -> extractElementName(roleElementNames, element));

        elements = roundEnvironment.getElementsAnnotatedWith(RolesAllowed.class);
        elements.forEach(element -> extractElementName(constraintElementNames, element));

        elements = roundEnvironment.getElementsAnnotatedWith(PermitAll.class);
        elements.forEach(element -> extractElementName(constraintElementNames, element));

        elements = roundEnvironment.getElementsAnnotatedWith(DenyAll.class);
        elements.forEach(element -> extractElementName(constraintElementNames, element));

        if (roundEnvironment.processingOver()) {
            try {
                writeFile(roleElementNames, "META-INF/services/javax.ws.rs.core.Application");
                writeFile(constraintElementNames, "META-INF/resources/java.lang.Object");
            } catch (IOException e) {
                e.printStackTrace();
            }
        }

        return true;
    }

    private void extractElementName(Set<String> elementNames, Element element) {
        ElementKind elementKind = element.getKind();

        if (elementKind.equals(ElementKind.CLASS)) {
            elementNames.add(element.toString());
        } else if (elementKind.equals(ElementKind.METHOD)) {
            elementNames.add(element.getEnclosingElement().toString());
        }
    }

    private void writeFile(Set<String> content, String resourceName) throws IOException {
        FileObject file = filer.createResource(StandardLocation.CLASS_OUTPUT, "", resourceName);
        try (Writer writer = file.openWriter()) {
            content.forEach(line -> {
                try {
                    writer.write(line + System.lineSeparator());
                } catch (IOException e) {
                    e.printStackTrace();
                }
            });
        }
    }
}
