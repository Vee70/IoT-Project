import os
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.metrics import confusion_matrix
from sklearn.preprocessing import LabelEncoder
from sklearn.preprocessing import OneHotEncoder

#############################
#####     Constants    ######
#############################
WINDOW_SIZE = 300
SKIP = 100

# path to data directory
current_dir = ''
data_path = current_dir + 'data/'
train_path = data_path + 'train/'
test_path = data_path + 'test/'
val_path = data_path + 'val/'
# path to models directory
model_path = current_dir + 'models/'

# selected devices
devices = [
    'amazonecho',
    'belkinwemomotionsensor',
    'belkinwemoswitch',
    'dropcam',
    'hpprinter',
    'ihome', # new
    'lightbulbslifxsmartbulb',
    'netatmoweatherstation',
    'netatmowelcome',
    'pix-starphoto-frame',
    'samsungsmartcam',
    'smartthings',
    'tp-linkdaynightcloudcamera', # new
    'tp-linksmartplug',
    'tribyspeaker',
    'withingsaurasmartsleepsensor', # new
    'withingssmartbabymonitor',
]

device_names = [
    'Amazon Echo',
    'Belkin Wemo Motion Sensor',
    'Belkin Wemo Switch',
    'Dropcam',
    'HP Printer',
    'iHome', # new
    'LiFX Smart Bulb',
    'Netatmo Weather Station',
    'Netatmo Welcome',
    'PIX-STAR Photo-frame',
    'Samsung SmartCam',
    'Smart Things',
    'TP-Link Day Night Cloud Camera', # new
    'TP-Link Smart Plug',
    'Triby Speaker',
    'Withings Aura Smart Sleep Sensor', # new
    'Withings Smart Baby Monitor', 
]

# get devices name and corresponding MAC address
devices_list = pd.read_csv(current_dir + 'DeviceList.csv')
devices_dict = devices_list.set_index('Device').loc[:, ['MAC']].loc[devices, :].to_dict()['MAC']

#############################
##### Data Preparation ######
#############################
def get_labels(dev_dict=devices_dict):
    mac_addr = np.array(list(dev_dict.values()))
    labels = pd.DataFrame.from_dict(dev_dict, orient='index').reset_index()
    labels.columns = ['Device', 'MAC_addr']
    # assigning numerical values using labelencoder
    label_encoder = LabelEncoder()
    labels['MAC_addr_cat'] = label_encoder.fit_transform(labels['MAC_addr'])
    # onehot encoder
    ohe = OneHotEncoder()
    ohe_df = pd.DataFrame(ohe.fit_transform(labels[['MAC_addr_cat']]).toarray())
    labels = labels.join(ohe_df)
    return labels

def load_data(path, dev_dict=devices_dict, labels=get_labels(), window_size=WINDOW_SIZE, skip=SKIP):
    X, y = [], []
    for f in os.listdir(path):
        if '.csv' not in f: continue
        df = pd.read_csv(path + f)
        # get device type
        device = f.split('_')[0]
        # total number of samples
        total_size = int(df.shape[0]/skip) - int(window_size/skip)
        for i in range(total_size):
            sample = df.iloc[i*skip:i*skip+window_size, 1:].copy().to_numpy()
            labels_tmp = labels[labels['MAC_addr'] == dev_dict[device]].iloc[:, 3:].to_numpy()
            # remove sample with all 0
            if np.array(sample).sum() == 0.0: continue
            X.append(sample)
            y.append(labels_tmp[0])
    return np.array(X), np.array(y)

# load data from a single csv file
def get_sample(df, device, labels=get_labels(), dev_dict=devices_dict, window_size=WINDOW_SIZE, skip=SKIP):
    total_size = int(df.shape[0]/skip) - int(window_size/skip)
    X, y = [], []
    for i in range(total_size):
        sample = df.iloc[i*skip:i*skip+window_size, 1:].copy().to_numpy()
        labels_tmp = labels[labels['MAC_addr'] == dev_dict[device]].iloc[:, 3:].to_numpy()
        if np.array(sample).sum() == 0.0: continue
        X.append(sample)
        y.append(labels_tmp[0])
    return np.array(X), np.array(y)

#############################
##### Confusion Matrix ######
#############################
l = get_labels()
l['Device_name'] = device_names

def plot_confusion_matrix(cm, devices, title='Confusion matrix', cmap=plt.cm.Blues):
    plt.figure(figsize=(18, 12))
    plt.title(title)
    tick_marks = np.arange(len(devices))
    sns.heatmap(cm, annot=True, cmap=cmap, fmt='.2%', xticklabels=devices, yticklabels=devices)
    plt.xlabel('Predicted label')
    plt.ylabel('True label')

def plot(y_pred, y_true, labels=l):
    cm = confusion_matrix(y_true.argmax(axis=1), y_pred.argmax(axis=1))
    cm_normalized = cm.astype('float') / cm.sum(axis=1)[:, np.newaxis]
    devices_list = labels.sort_values(by='MAC_addr_cat')['Device_name'].values
    plot_confusion_matrix(cm_normalized, devices_list)

# def plot_confusion_matrix(cm, devices, title='Confusion matrix', cmap=plt.cm.Blues):
#     plt.figure(figsize=(16, 10))
#     plt.title(title)
#     tick_marks = np.arange(len(devices))
#     sns.heatmap(cm, annot=True, cmap=cmap, xticklabels=devices, yticklabels=devices)
#     plt.xlabel('Predicted label')
#     plt.ylabel('True label')

# def plot(y_pred, y_true, labels=l):
#     cm = confusion_matrix(y_true.argmax(axis=1), y_pred.argmax(axis=1))
#     # cm_normalized = cm.astype('float') / cm.sum(axis=1)[:, np.newaxis]
#     devices_list = labels.sort_values(by='MAC_addr_cat')['Device_name'].values
#     plot_confusion_matrix(cm, devices_list)

#############################
########### Test ############
#############################
def get_predicted_values(model, path):
    y_pred, y_true = [], []
    # iterate through each csv files in data path
    for f in os.listdir(path):
        if '.csv' not in f: continue
        # get name of the device
        device = f.split('_')[0]
        df = pd.read_csv(path + f)
        # get sample of the device
        X_test, y_test = get_sample(df, device)
        # X_test = scaler.transform(X_test.reshape(-1, n_features))
        # X_test = X_test.reshape(-1, n_timesteps, n_features)
        # get prediction
        y_pred.extend(model.predict(X_test))
        # get true values
        y_true.extend(y_test)
    y_pred, y_true = np.array(y_pred), np.array(y_true)
    return y_pred, y_true
