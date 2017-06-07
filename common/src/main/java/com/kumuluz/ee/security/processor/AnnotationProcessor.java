/*
 *  Copyright (c) 2014-2017 Kumuluz and/or its affiliates
 *  and other contributors as indicated by the @author tags and
 *  the contributor list.
 *
 *  Licensed under the MIT License (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  https://opensource.org/licenses/MIT
 *
 *  The software is provided "AS IS", WITHOUT WARRANTY OF ANY KIND, express or
 *  implied, including but not limited to the warranties of merchantability,
 *  fitness for a particular purpose and noninfringement. in no event shall the
 *  authors or copyright holders be liable for any claim, damages or other
 *  liability, whether in an action of contract, tort or otherwise, arising from,
 *  out of or in connection with the software or the use or other dealings in the
 *  software. See the License for the specific language governing permissions and
 *  limitations under the License.
 */
package com.kumuluz.ee.security.processor;

import com.kumuluz.ee.security.annotations.Keycloak;
import com.kumuluz.ee.security.annotations.Secure;

import javax.annotation.processing.AbstractProcessor;
import javax.annotation.processing.Filer;
import javax.annotation.processing.ProcessingEnvironment;
import javax.annotation.processing.RoundEnvironment;
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
import java.io.*;
import java.lang.annotation.Annotation;
import java.util.*;

/**
 * Compile-time annotation processor for DeclareRoles, RolesAllowed, PermitAll and DenyAll annotations. Generates service file.
 *
 * @author Benjamin Kastelic
 */
public class AnnotationProcessor extends AbstractProcessor {

    private Filer filer;

    private List<Class<? extends Annotation>> securityProviders = Arrays.asList(Keycloak.class);

    // classes with @DeclareRoles annotation
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
        Set<? extends Element> elements;

        for (Class<? extends Annotation> securityProvider : securityProviders) {
            elements = roundEnvironment.getElementsAnnotatedWith(securityProvider);
            elements.forEach(element -> extractElementName(roleElementNames, element));
        }

        elements = roundEnvironment.getElementsAnnotatedWith(DeclareRoles.class);
        elements.forEach(element -> extractElementName(roleElementNames, element));

        elements = roundEnvironment.getElementsAnnotatedWith(RolesAllowed.class);
        elements.forEach(element -> extractElementName(constraintElementNames, element));

        elements = roundEnvironment.getElementsAnnotatedWith(PermitAll.class);
        elements.forEach(element -> extractElementName(constraintElementNames, element));

        elements = roundEnvironment.getElementsAnnotatedWith(DenyAll.class);
        elements.forEach(element -> extractElementName(constraintElementNames, element));

        try {
            writeFile(roleElementNames, "META-INF/services/javax.ws.rs.core.Application");
            writeFile(constraintElementNames, "META-INF/resources/java.lang.Object");
        } catch (IOException e) {
            e.printStackTrace();
        }

        return true;
    }

    private void extractElementName(Set<String> elementNames, Element element) {
        ElementKind elementKind = element.getKind();

        if (elementKind.equals(ElementKind.CLASS) && !isCdiSecurityEnabled(element)) {
            elementNames.add(element.toString());
        } else if (elementKind.equals(ElementKind.METHOD) && !isCdiSecurityEnabled(element.getEnclosingElement())) {
            elementNames.add(element.getEnclosingElement().toString());
        }
    }

    private boolean isCdiSecurityEnabled(Element element) {
        return element.getAnnotation(Secure.class) != null;
    }

    private void writeFile(Set<String> content, String resourceName) throws IOException {
        FileObject file = readOldFile(content, resourceName);
        if (file != null) {
            try {
                writeFile(content, resourceName, file);
                return;
            } catch (IllegalStateException e) {
                e.printStackTrace();
            }
        }
        writeFile(content, resourceName, null);
    }
    private void writeFile(Set<String> content, String resourceName, FileObject overrideFile) throws IOException {
        FileObject file = overrideFile;
        if (file == null) {
            file = filer.createResource(StandardLocation.CLASS_OUTPUT, "", resourceName);
        }
        try (Writer writer = file.openWriter()) {
            for (String serviceClassName : content) {
                writer.write(serviceClassName);
                writer.write(System.lineSeparator());
            }
        }
    }
    private FileObject readOldFile(Set<String> content, String resourceName) throws IOException {
        Reader reader = null;
        try {
            final FileObject resource = filer.getResource(StandardLocation.CLASS_OUTPUT, "", resourceName);
            reader = resource.openReader(true);
            readOldFile(content, reader);
            return resource;
        } catch (FileNotFoundException e) {
            // close reader, return null
        } finally {
            if (reader != null) {
                reader.close();
            }
        }
        return null;
    }
    private static void readOldFile(Set<String> content, Reader reader) throws IOException {
        try (BufferedReader bufferedReader = new BufferedReader(reader)) {
            String line = bufferedReader.readLine();
            while (line != null) {
                content.add(line);
                line = bufferedReader.readLine();
            }
        }
    }
}
