#
from gensim.models.doc2vec import Doc2Vec, TaggedDocument
from nltk.tokenize import word_tokenize
from sklearn import model_selection
from sklearn.linear_model import LogisticRegression
from urllib.parse import unquote
import numpy as np
import pandas as pd
import csv
import urllib.parse as parse
import pickle
import sys

np.random.seed(42)

filename1 = 'lib/DecisionTreeClassifier.sav'
filename2 = 'lib/SVC.sav'
filename3 = 'lib/GaussianNB.sav'
filename4 = 'lib/KNeighborsClassifier.sav'
filename5 = 'lib/RandomForestClassifier.sav'
filename6 = 'lib/MLPClassifier.sav'
# load the models from disk
loaded_model1 = pickle.load(open(filename1, 'rb'))
loaded_model2 = pickle.load(open(filename2, 'rb'))
loaded_model3 = pickle.load(open(filename3, 'rb'))
loaded_model4 = pickle.load(open(filename4, 'rb'))
loaded_model5 = pickle.load(open(filename5, 'rb'))
loaded_model6 = pickle.load(open(filename6, 'rb'))
model= Doc2Vec.load("lib/d2v.model")

# Create a function to convert an array of strings to a set of features
def getVec(text):
    features = []
    for i, line in enumerate(text):
        test_data = word_tokenize(line.lower())
        v1 = model.infer_vector(test_data)
        #print("V1_infer", v1)
        featureVec = v1
        #print(featureVec)
        lineDecode = unquote(line)
        lowerStr = str(lineDecode).lower()
        #print("X "+str(i)+"=> "+lowerStr)
        # add feature for malicious tag count
        feature1 = int(lowerStr.count('link'))
        feature1 += int(lowerStr.count('object'))
        feature1 += int(lowerStr.count('form'))
        feature1 += int(lowerStr.count('embed'))
        feature1 += int(lowerStr.count('ilayer'))
        feature1 += int(lowerStr.count('layer'))
        feature1 += int(lowerStr.count('style'))
        feature1 += int(lowerStr.count('applet'))
        feature1 += int(lowerStr.count('meta'))
        feature1 += int(lowerStr.count('img'))
        feature1 += int(lowerStr.count('iframe'))
        feature1 += int(lowerStr.count('marquee'))
        # add feature for malicious method count
        feature2 = int(lowerStr.count('exec'))
        feature2 += int(lowerStr.count('fromcharcode'))
        feature2 += int(lowerStr.count('eval'))
        feature2 += int(lowerStr.count('alert'))
        feature2 += int(lowerStr.count('getelementsbytagname'))
        feature2 += int(lowerStr.count('write'))
        feature2 += int(lowerStr.count('unescape'))
        feature2 += int(lowerStr.count('escape'))
        feature2 += int(lowerStr.count('prompt'))
        feature2 += int(lowerStr.count('onload'))
        feature2 += int(lowerStr.count('onclick'))
        feature2 += int(lowerStr.count('onerror'))
        feature2 += int(lowerStr.count('onpage'))
        feature2 += int(lowerStr.count('confirm'))
        # add feature for ".js" count
        feature3 = int(lowerStr.count('.js'))
        # add feature for "javascript" count
        feature4 = int(lowerStr.count('javascript'))
        # add feature for length of the string
        feature5 = int(len(lowerStr))
        # add feature for "<script"  count
        feature6 = int(lowerStr.count('script'))
        feature6 += int(lowerStr.count('<script'))
        feature6 += int(lowerStr.count('&lt;script'))
        feature6 += int(lowerStr.count('%3cscript'))
        feature6 += int(lowerStr.count('%3c%73%63%72%69%70%74'))
        # add feature for special character count
        feature7 = int(lowerStr.count('&'))
        feature7 += int(lowerStr.count('<'))
        feature7 += int(lowerStr.count('>'))
        feature7 += int(lowerStr.count('"'))
        feature7 += int(lowerStr.count('\''))
        feature7 += int(lowerStr.count('/'))
        feature7 += int(lowerStr.count('%'))
        feature7 += int(lowerStr.count('*'))
        feature7 += int(lowerStr.count(';'))
        feature7 += int(lowerStr.count('+'))
        feature7 += int(lowerStr.count('='))
        feature7 += int(lowerStr.count('%3C'))
        # add feature for http count
        feature8 = int(lowerStr.count('http'))
        
        # append the features
        featureVec = np.append(featureVec,feature1)
        featureVec = np.append(featureVec,feature2)
        featureVec = np.append(featureVec,feature3)
        featureVec = np.append(featureVec,feature4)
        featureVec = np.append(featureVec,feature5)
        featureVec = np.append(featureVec,feature6)
        featureVec = np.append(featureVec,feature7)
        featureVec = np.append(featureVec,feature8)
        #print(featureVec)
        features.append(featureVec)
        #print(features)
    return features



f = open('lib/test.txt', 'r')
testXSS = f.readlines()
Xnew = getVec(testXSS)
f.close()
print("")

# make a prediction
#1 DecisionTreeClassifier
ynew1 = loaded_model1.predict(Xnew)
#2 SVC
ynew2 = loaded_model2.predict(Xnew)
#3 GaussianNB
ynew3 = loaded_model3.predict(Xnew)
#4 KNeighborsClassifier
ynew4 = loaded_model4.predict(Xnew)
#5 RandomForestClassifier
ynew5 = loaded_model5.predict(Xnew)
#6 MLPClassifier
ynew6 = loaded_model6.predict(Xnew)

# show the sample inputs and predicted outputs
xssCount = 0 
notXssCount = 0
for i in range(len(Xnew)):
    score = ((.175*ynew1[i])+(.15*ynew2[i])+(.05*ynew3[i])+(.075*ynew4[i])+(.25*ynew5[i])+(.3*ynew6[i]))
    #print(ynew1[i])
    #print(ynew2[i])
    #print(ynew3[i])
    #print(ynew4[i])
    #print(ynew5[i])
    #print(ynew6[i])
    print()
    print(score)
    if score >= .5:
        print("\033[1;31;1mXSS\033[0;0m => "+testXSS[i])
        xssCount += 1
    else:
        #print(ynew1[i])
        #print(ynew2[i])
        #print(ynew3[i])
        #print(ynew4[i])
        #print(ynew5[i])
        #print(ynew6[i])
        #print(score)
        print("\033[1;32;1mNOT XSS\033[0;0m => "+testXSS[i])
        notXssCount += 1

print()
print("*------------- RESULTS -------------*")
print("\033[1;31;1mXSS\033[0;0m => "+str(xssCount))
print("\033[1;32;1mNOT XSS\033[0;0m => "+str(notXssCount))
