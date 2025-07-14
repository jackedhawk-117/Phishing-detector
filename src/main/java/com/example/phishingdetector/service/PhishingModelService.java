package com.example.phishingdetector.service;

import com.example.phishingdetector.util.EmailFeatureExtractor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import weka.classifiers.Classifier;
import weka.classifiers.evaluation.Evaluation;
import weka.classifiers.trees.RandomForest;
import weka.core.*;
import weka.core.converters.ConverterUtils.DataSource;
import weka.filters.Filter;
import weka.filters.unsupervised.attribute.StringToWordVector;

import javax.annotation.PostConstruct;
import java.io.InputStream;
import java.util.*;
import java.util.concurrent.atomic.AtomicReference;

@Service
public class PhishingModelService {
    private AtomicReference<Classifier> model = new AtomicReference<>();
    private AtomicReference<Instances> structure = new AtomicReference<>();
    private Instances originalStructure;
    private StringToWordVector textFilter;
    private double currentAccuracy;

    @Value("${model.retrain.threshold:0.05}")
    private double accuracyImprovementThreshold;

    private static final Set<String> BLACKLISTED_DOMAINS = new HashSet<>(Arrays.asList(
            "free-gifts.tk", "bank-update.xyz", "verify-account.com",
            "secure-login.net", "update-info.com", "account-alert.org"
    ));

    @PostConstruct
    public void initialize() throws Exception {
        trainModel();
    }

    @Scheduled(fixedRate = 86400000) // Daily retraining
    public void scheduleRetraining() throws Exception {
        trainModel();
    }

    private void trainModel() throws Exception {
        try (InputStream is = getClass().getResourceAsStream("/data/emails.arff")) {
            DataSource source = new DataSource(is);
            Instances data = source.getDataSet();
            data.setClassIndex(data.numAttributes() - 1);
            this.originalStructure = new Instances(data, 0);

            configureTextFilter(data);
            Instances filteredData = Filter.useFilter(data, textFilter);

            Classifier newModel = new RandomForest();
            newModel.buildClassifier(filteredData);

            double newAccuracy = evaluateModel(filteredData);

            if (newAccuracy > currentAccuracy + accuracyImprovementThreshold) {
                this.model.set(newModel);
                this.structure.set(new Instances(filteredData, 0));
                this.currentAccuracy = newAccuracy;
                System.out.printf("Model updated with accuracy: %.2f%%\n", newAccuracy * 100);
            }
        }
    }

    public double score(String emailText) throws Exception {
        Instance inst = createInstanceFromText(emailText, null);
        Instances singleInstance = new Instances(originalStructure, 0);
        singleInstance.add(inst);
        singleInstance = Filter.useFilter(singleInstance, textFilter);

        double[] dist = model.get().distributionForInstance(singleInstance.firstInstance());
        double baseScore = dist[structure.get().classAttribute().indexOfValue("phishing")];

        return adjustScoreWithFeatures(baseScore, emailText);
    }

    private double adjustScoreWithFeatures(double baseScore, String emailText) {
        // Domain-based adjustment
        String domain = EmailFeatureExtractor.extractDomain(emailText);
        if (domain != null && BLACKLISTED_DOMAINS.contains(domain)) {
            baseScore = Math.min(1.0, baseScore + 0.3);
        }

        // Feature-based adjustments
        if (EmailFeatureExtractor.hasSpoofedBrands(emailText)) {
            baseScore = Math.min(1.0, baseScore + 0.15);
        }

        double linkRatio = EmailFeatureExtractor.linkToTextRatio(emailText);
        if (linkRatio > 0.2) { // More than 20% of text is links
            baseScore = Math.min(1.0, baseScore + (linkRatio * 0.5));
        }

        return baseScore;
    }

    private Instance createInstanceFromText(String text, String classValue) {
        Instance inst = new DenseInstance(4);
        inst.setDataset(originalStructure);

        inst.setValue(0, originalStructure.attribute(0).addStringValue(text));
        inst.setValue(1, EmailFeatureExtractor.containsUrl(text) ? 1 : 0);
        inst.setValue(2, EmailFeatureExtractor.countUrgencyWords(text));

        if (classValue != null) {
            inst.setClassValue(classValue);
        }

        return inst;
    }

    private double evaluateModel(Instances data) throws Exception {
        Evaluation eval = new Evaluation(data);
        int folds = Math.min(10, data.numInstances());

        if (folds > 1) {
            eval.crossValidateModel(model.get(), data, folds, new Random(1));
        } else {
            eval.evaluateModel(model.get(), data);
        }

        return eval.pctCorrect() / 100;
    }

    private void configureTextFilter(Instances data) throws Exception {
        textFilter = new StringToWordVector();
        textFilter.setLowerCaseTokens(true);
        textFilter.setIDFTransform(true);
        textFilter.setTFTransform(true);
        textFilter.setInputFormat(data);
    }

    public boolean isBlacklistedDomain(String domain) {
        return BLACKLISTED_DOMAINS.contains(domain);
    }
}