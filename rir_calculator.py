### RIR Calculator
    ## Features
        # Selection of attributes
    ## Calculating Parameters
        # Order of attributes which gives the highest mean RIR
        # Highest mean RIR
        # k-anonymity
        # l-diversity
        # t-closeness
import time
from timeit import default_timer as timer
import tkinter as tk
import pandas as pd
import numpy as np
from tkinter import filedialog
from tkinter.filedialog import askopenfile
import pandastable as pt
import datetime
import os

from scoring_sys_evaluation.uniqueness_risk import calc_uniqueness_risk_parameters
from scoring_sys_evaluation.uniformity_risk import calc_uniformity_risk_parameters
from scoring_sys_evaluation.correlation_risk import calc_correlation_risk_parameters
from scoring_sys_evaluation.mm_risk import calc_mm_risk_parameters, calc_mm_risk_with_uq_uf_co
from scoring_sys_evaluation.combine_qi import combine_known_attributes

#from markov_model_reidentification_risk.mm_workflow import find_workflow
from anonymetrics.anonymetrics import calculate_k_anonymity, calculate_l_diversity, calculate_t_closeness
from gui.risk_analysis import risk_analysis

# Create an interface window
root = tk.Tk()
#root.geometry('450x700')                # Window size

#getting screen width and height of display
width= root.winfo_screenwidth()
height= root.winfo_screenheight()

#setting tkinter window size
root.geometry("%dx%d" % (width, height))

root.title('RIR Calculator V3.0')       # Window title

# Initialize variables for tkinter
rir_mean = tk.StringVar()
attri_order = tk.StringVar()
r_uq = tk.StringVar()       # Uniqueness-only Risk
r_uf = tk.StringVar()       # Uniformity-only Risk
r_uquf = tk.StringVar()     # Uniqueness & Uniformity Risk
r_mm_tm1 = tk.StringVar()   # MM Risk of Threat Model 2 : The data custodian is aware of the intruder’s background knowledge
r_mm_tm2 = tk.StringVar()   # MM Risk of Threat Model 2 : The data custodian is not aware of the intruder’s background knowledge
exec_time_tk = tk.StringVar()

k_anon = tk.StringVar()
l_dive = tk.StringVar()
t_clos = tk.StringVar()
dataset_info = tk.StringVar()
#results_tktable = pt.Table(showtoolbar=True, showstatusbar=False, width=680, height=350)

#dataset
attribute_list = []
no_records = 0
csv_file_path = ''
nan_count = 0

r_uq.set('                                                  ')
r_uf.set('                                                  ')
r_mm_tm1.set('                                                  ')
r_mm_tm2.set('                                                  ')
k_anon.set('                                                  ')
l_dive.set('                                                  ')
t_clos.set('                                                  ')

# Initialize global variables
df = pd.DataFrame()
summery_df = pd.DataFrame(columns=['Metric', 'Attributes', 'Min', 'Max', 'Mean', 'Excec Time (ms)'])
attribute_list = []
qi_checkbox_dict = {}
sa_checkbox_dict = {}
event_level_radiobtn_dict = {}
uid_radiobtn_dict = {}

def open_file():
    # Function for opening the dataset of csv files
    global dataset
    global attribute_list
    global no_records
    global csv_file_path
    global nan_count
    clear_all_data()

    csv_file_path = askopenfile(mode='r', filetypes = [('csv files', '*.csv')])
    
    if csv_file_path is not None:
        dataset = pd.read_csv(csv_file_path)
        attribute_list = list(dataset.head())
        no_records = dataset.shape[0]
        nan_count = dataset.isna().sum().sum()      # Count NaN values
        dataset = dataset.fillna(0)                 # Fill NaN with 0
        #dataset = dataset.dropna(axis=0)            # drop the row with NaN values
        dataset_info.set('Dataset loaded.  No of attributes : ' + str(len(attribute_list)) + '  No of records : ' + str(no_records))
        dataset_popup()
def dataset_popup():
    
    event_level = tk.IntVar()
    uid_label = tk.StringVar()
    user_id = tk.IntVar()

    top = tk.Toplevel(root)
    top.geometry("350x550")
    top.title("Dataset Configuration")
    def create_uid_radiobtns():

        # Create a frame
        uid_select_frame = tk.LabelFrame(top, text=' User ID Attribute ')
        uid_select_frame.grid(row=1, column=0, columnspan=2, padx=15, pady=15, sticky=tk.W)

        # Create radio button list for userID
        for i in range(len(attribute_list)):

            # First column
            if i <= 20:
                uid_radiobtn = tk.Radiobutton(uid_select_frame, text=attribute_list[i], variable=user_id, value=i)
                uid_radiobtn.grid(row=i+1, column=0, columnspan=1, padx=0, pady=0, sticky=tk.W)
                uid_radiobtn_dict[i] = uid_radiobtn  # Keep reference for each radiobutton in a dictionary

            # Second column
            else:
                uid_radiobtn = tk.Radiobutton(uid_select_frame, text=attribute_list[i], variable=user_id, value=i)
                uid_radiobtn.grid(row=i-20, column=1, columnspan=1, padx=0, pady=0, sticky=tk.W)
                uid_radiobtn_dict[i] = uid_radiobtn

    def clear_uid_radiobtns():

        for i in range(len(attribute_list)):
            uid_radiobtn = uid_radiobtn_dict[i]
            uid_radiobtn.destroy()
    def update_uid():
        # Get selected attribute as userID
        global attribute_list
        uid_attri = attribute_list[user_id.get()]
        if event_level.get() == 1:
            dataset.rename(columns={uid_attri: "userID"}, inplace=True)
            uid_label.set(dataset.columns)

        if event_level.get() == 2:
            dataset.insert(0, 'userID', range(0, len(dataset)))


        attribute_list = list(dataset.head())
        attribute_list.remove('userID')     # Get the attributes without 'userID'
        create_checkboxes()  # Creating checkboxes for attributes to select them
        top.destroy()

    ## Frames
    dataset_catogory_frame = tk.LabelFrame(top, text=' Dataset Catogory ')
    dataset_catogory_frame.grid(row=0, column=0, columnspan=1, padx=15, pady=15, sticky=tk.W)


    ## Dataset Category - Radio-buttons
    tk.Radiobutton(dataset_catogory_frame, text="Event-level Data", padx=10, variable=event_level, value=1,
                   command=create_uid_radiobtns).grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
    tk.Radiobutton(dataset_catogory_frame, text="Person-level Data", padx=10, variable=event_level, value=2,
                   command=clear_uid_radiobtns).grid(row=1, column=0, padx=5, pady=5, sticky=tk.W)

    btn_ok = tk.Button(top, text='OK', command=update_uid, width=10).grid(row=0, column=1, padx=10, pady=10, sticky=tk.W)
    #lbl_uid = tk.Label(top, textvariable=uid_label).pack()
def create_checkboxes():
    # The function to create checkboxes for attributes to select them

    for i in range(len(attribute_list)):
        ## For QI
        qi_checkbox = tk.Checkbutton(qi_cb_frame, text=attribute_list[i])
        qi_checkbox.grid(row=i+7, column=1, padx=1, pady=1, sticky=tk.W)
        qi_checkbox_dict[i] = qi_checkbox        # Keep reference for each checkbox in a dictionary

        ## For SA
        sa_checkbox = tk.Checkbutton(sa_cb_frame, text=attribute_list[i])
        sa_checkbox.grid(row=i+7, column=2, padx=1, pady=1, sticky=tk.W)
        sa_checkbox_dict[i] = sa_checkbox  # Keep reference for each checkbox in a dictionary
def get_checkbox_status():
    ## Function to get the check status of check boxes
        # Return
            # List of indices of selected QI        : for k & l
            # List of indices of selected SA        : for l
            # List of all selected attribute names  : for RIR

    attri_list = []    # A list of names of attributes selected by the user
    qi_list = []       # A list of names of qi selected by the user
    qi_indices = []    # A list of index of QI selected by the user
    sa_indices = []    # A list of index of SA selected by the user
    sa_list = []       # A list of names of SA selected by the user

    # Get attribute selection checkbox status
    for i in range(len(attribute_list)):
        qi_cb = qi_checkbox_dict[i]
        qi_cb_varname = qi_cb.cget("variable")
        qi_cb_value = root.getvar(qi_cb_varname)  # If checked cb_value = 1 else cb_value = 0

        if qi_cb_value == '1':
            attri_list.append(attribute_list[i])
            qi_indices.append(i + 1)  # i+1 because userID column (i=0) is already removed
            qi_list.append(attribute_list[i])

        sa_cb = sa_checkbox_dict[i]
        sa_cb_varname = sa_cb.cget("variable")
        sa_cb_value = root.getvar(sa_cb_varname)  # If checked cb_value = 1 else cb_value = 0

        if sa_cb_value == '1':
            attri_list.append(attribute_list[i])
            sa_indices.append(i + 1)  # i+1 because userID column (i=0) is already removed
            sa_list.append(attribute_list[i])

        if qi_cb_value == '1' and sa_cb_value == '1':
            selct_err = tk.messagebox.showerror(title='Selection Error', message='Same attributes are selected as both QI & SA')
            clear_output_data()     # Clear results if available

    if not qi_indices:             # If qi_indices is empty --> True
        qi_err = tk.messagebox.showerror(title='Selection Error', message='QIs are not selected !')
        clear_output_data()         # Clear results if available

    return attri_list,qi_list, qi_indices,sa_list, sa_indices
def get_max_risks(df : pd.DataFrame, metric : str):

    max_risk = []
    ind = df.index[df['Metric'] == metric].tolist()
    for i in ind:
       max_risk.append(df.loc[i]['Max'])

    return max(max_risk)
def calc_risk_parameter():
    ### The function to calculate the risk parameters

    ## Clear all output data if available
    clear_output_data()

    ## Check for non-empty df
    if dataset.empty:            # If df is empty --> True
        df_err = tk.messagebox.showerror(title='Dataset Error', message='A dataset is not loaded !')

    ## Get checkbox status
    attri_list,qi_list, qi_indices, sa_list, sa_indices = get_checkbox_status()

    #start_time = timer() * 10**3

    ## Create combined df combining all QI values
    time_tag_1 = timer() * 10 ** 3
    combined_df, columns_list = combine_known_attributes(df=dataset, known_attributes=qi_list, remaining_attributes=['userID'] + sa_list)
    time_tag_2 = timer() * 10 ** 3
    combine_time = round(time_tag_2 - time_tag_1, 3)

    # R-uq : All QIs with Combined df
    time_tag_1 = timer() * 10 ** 3
    uq_series, mm_occurrence  = calc_uniqueness_risk_parameters(combined_df, 'combined_qi')
    time_tag_2 = timer() * 10 ** 3
    # dataset['R_uq-TM1'] = uq_series
    uq_results = ['R_uq', 'All QIs', round(uq_series.min(), 3), round(uq_series.max(), 3), round(uq_series.mean(), 3),
                  time_tag_2 - time_tag_1]

    summery_df.loc[len(summery_df)] = uq_results

    # R-uf : All QIs
    time_tag_1 = timer() * 10**3
    uf_series = calc_uniformity_risk_parameters(df=combined_df, selected_attribute='combined_qi')
    time_tag_2 = timer() * 10**3
    mm_uf_qi = uf_series  # Keep for R-mm calculation
    uf_results = ['R_uf', 'All QIs', round(uf_series.min(),3), round(uf_series.max(),3), round(uf_series.mean(),3),time_tag_2 - time_tag_1]

    summery_df.loc[len(summery_df)] = uf_results
    #dataset['R_uf-All QIs'] = uf_series

    # R-uf : Single QIs
    for attri in qi_list:
        time_tag_1 = timer() * 10**3
        uf_series = calc_uniformity_risk_parameters(df=dataset, selected_attribute=attri)
        time_tag_2 = timer() * 10**3
        uf_results = ['R_uf', attri, round(uf_series.min(),3), round(uf_series.max(),3), round(uf_series.mean(),3), time_tag_2 - time_tag_1]
        summery_df.loc[len(summery_df)] = uf_results
        #dataset['R_uf - ' + attri] = uf_series

    # R-co
    for i in range(len(qi_list)):
        for k in range(len(sa_list)):
            time_tag_1 = timer() * 10**3
            co_series = calc_correlation_risk_parameters(df=dataset, attri1=qi_list[i], attri2=sa_list[k])
            time_tag_2 = timer() * 10**3
            co_results = ['R_co', qi_list[i] + ' - ' + sa_list[k], round(co_series.min(),3), round(co_series.max(),3), round(co_series.mean(),3), time_tag_2 -time_tag_1]
            summery_df.loc[len(summery_df)] = co_results
            #dataset['R_co - ' + qi_list[i] + ' - ' + sa_list[k]] = co_series

    ## R-mm : TM 1
    # R-uf for SA for R-mm
    time_tag_1 = timer() * 10 ** 3
    mm_uf_sa = calc_uniformity_risk_parameters(df=combined_df, selected_attribute=sa_list[0])

    # R-co for all QIs for R-mm
    mm_trans_prob = calc_correlation_risk_parameters(df=combined_df, attri1='combined_qi', attri2=sa_list[0])

    #mm_series = calc_mm_risk_parameters(df=combined_df, sensitive_attri=['combined_qi'] + [attri])
    mm_series = calc_mm_risk_with_uq_uf_co(mm_occurrence, mm_uf_qi, mm_trans_prob, mm_uf_sa, no_records)
    time_tag_2 = timer() * 10**3
    mm_results = ['R_mm', 'All QIs - ' + sa_list[0], round(mm_series.min(),3), round(mm_series.max(),3), round(mm_series.mean(),3), time_tag_2 - time_tag_1]
    summery_df.loc[len(summery_df)] = mm_results
    #dataset['R_mm - All QIs to ' + attri] = mm_series

    # Threat Model 2 : R-mm
    #arr_o, max_pr_mean = find_workflow(df=dataset, attributes=qi_list + sa_list, theta=1)

    # k, l & t
    time_tag_1 = timer() * 10**3
    k_value = calculate_k_anonymity(df=dataset, qa_indices=qi_indices)
    time_tag_2 = timer() * 10**3

    l_value = calculate_l_diversity(df=dataset, qa_indices=qi_indices, sa_indices=sa_indices[0])
    time_tag_3 = timer() * 10**3

    t_value = calculate_t_closeness(df=dataset, qa_indices=qi_indices,sa_index=sa_indices[0])
    time_tag_4 = timer() * 10**3

    summery_df.loc[len(summery_df)] = [None, None, None, None, None, None]
    summery_df.loc[len(summery_df)] = ['k-anonymity', 'All QIs', k_value, '*****', '*****', time_tag_2 - time_tag_1]
    summery_df.loc[len(summery_df)] = ['l-diversity', sa_list[0], l_value, '*****', '*****', time_tag_3 - time_tag_2]
    summery_df.loc[len(summery_df)] = ['t-closeness', sa_list[0], t_value, '*****', '*****', time_tag_4 - time_tag_3]

    summery_df['Excec Time (ms)'] = summery_df['Excec Time (ms)'].round(decimals=2)

    sa_uniques = dataset[sa_list[0]].unique().size

    # Add dataset details
    csv_file_name = os.path.basename(csv_file_path.name)
    summery_df.loc[len(summery_df)] = [None, None, None, None, None, None]
    summery_df.loc[len(summery_df)] = ['CSV File Path', csv_file_path.name, None, None, None, None]
    summery_df.loc[len(summery_df)] = ['CSV File Name', csv_file_name , None, None, None, None]
    summery_df.loc[len(summery_df)] = ['No of Records',no_records , None, None, None, None]
    summery_df.loc[len(summery_df)] = ['No of QIs', len(qi_list), None, None, None, None]
    summery_df.loc[len(summery_df)] = ['No of Nan', nan_count, None, None, None, None]
    summery_df.loc[len(summery_df)] = ['Combine time', combine_time, None, None, None, None]
    summery_df.loc[len(summery_df)] = ['Uniques of SA', sa_uniques, None, None, None, None]

    #global results_tktable
    results_tktable = pt.Table(results_frame, dataframe=summery_df, showtoolbar=True, showstatusbar=False, width=680, height=350)
    results_tktable.show()

    #conv_metric_df = pd.DataFrame({'SAs': sa_list, 'l-diversity': l_value, 't-closeness': t_value})

    #dataset['Results'] = ['k-anonymity : ', k_value, 'l-diversity', l_value, 't-closeness', t_value,
    #                       '*', '*', '*', '*', '*', '*', '*', '*', '*', '*']
    #print('*******************************************************************')
    #print(dataset)
    #print('k-anonymity : ' + str(k_value))
    #print('TM2 -   Highest R-mm mean : ' + str(max_pr_mean) + 'Order : ' + str(arr_o))

    #print(conv_metric_df)
    #conven_metrics_string = '\n\nk-anonymity \t: ' + str(k_value) + '\nl-diversity \t: ' + str(l_value) + '\nt-closeness \t: ' + str(t_value)
    #exten_metrics_string = ''
    #results_text.insert(tk.END, conven_metrics_string)

    path = 'E:\TC Vilshofen\Evaluation Results\Eval_Results - ' + csv_file_name.replace(".csv", "") + ' - ' + datetime.datetime.today().strftime('%m-%d-%Y_%H.%M.%S') + '.csv'
    summery_df.to_csv(path)

    ## Risk Analysis

    # Get max risks
    r_uq_max = get_max_risks(df=summery_df, metric='R_uq')
    r_uf_max = get_max_risks(df=summery_df, metric='R_uf')
    r_co_max = get_max_risks(df=summery_df, metric='R_co')

    # Get colors for indicators and configure
    color_list = risk_analysis(k_value, l_value, t_value,r_uq_max, r_uf_max , r_co_max,sa_uniques)
    cir_list = [cir_k, cir_l,cir_t, cir_conven_metrics,cir_uq, cir_uf, cir_co, cir_exten_metrics, cir_overview]
    canvas_list = [canvas_1, canvas_1, canvas_1, canvas_1, canvas_2, canvas_2, canvas_2, canvas_2, canvas_3]

    for i in range(len(color_list)):
        canvas_list[i].itemconfig(cir_list[i], fill=color_list[i])


def clear_output_data():
    # The function to clear the obtained results
    global summery_df
    rir_mean.set('')
    attri_order.set('')
    r_uq.set('')
    r_uf.set('')
    r_mm_tm1.set('')
    r_mm_tm2.set('')
    k_anon.set('')
    l_dive.set('')
    t_clos.set('')
    #reco_conven_text.delete("1.0","end")
    #reco_exten_text.delete("1.0", "end")
    #reco_mm_text.delete("1.0", "end")
    exec_time_tk.set('')
    #results_tktable.remove()
    #summery_df.iloc[0:0]

    #summery_df = pd.DataFrame(None)
    summery_df = pd.DataFrame(columns=['Metric', 'Attributes', 'Min', 'Max', 'Mean', 'Excec Time (ms)'])
def clear_checkboxes():
    # Clear the attribute checkboxes
    for i in range(len(attribute_list)):
        qi_cb = qi_checkbox_dict[i]
        qi_cb.destroy()
        sa_cb = sa_checkbox_dict[i]
        sa_cb.destroy()

    dataset_info.set('')
def clear_all_data():
    # Clear the attribute checkboxes and obtained results
    clear_output_data()
    clear_checkboxes()

### Widgets creating

# Buttons
btn_open = tk.Button(root, text='Load Dataset', command = open_file, width=15)
btn_open.grid(row=0, column=0, padx=10, pady=10)

btn_calculate = tk.Button(root, text='Calculate', command=calc_risk_parameter, width=10)
btn_calculate.grid(row=0, column=1, padx=10, pady=10)

btn_clear = tk.Button(root, text='Clear', command = clear_output_data, width=10)
btn_clear.grid(row=0, column=2, padx=10, pady=10)

# Frames
results_frame = tk.LabelFrame(root, text=' Results ', width=200, height=30)
results_frame.grid(row=2, column=0, rowspan=8, columnspan=2, padx=10, pady=10, sticky=tk.W)

qi_cb_frame = tk.LabelFrame(root, text=' QI Selection ')
qi_cb_frame.grid(row=4, column=3, padx=10, pady=10, sticky=tk.N)

sa_cb_frame = tk.LabelFrame(root, text=' SA Selection ')
sa_cb_frame.grid(row=4, column=4, padx=10, pady=10, sticky=tk.N)

reco_conven_frame = tk.LabelFrame(root, text=' Conventional Metrics ', width=13, height=22)
reco_conven_frame.grid(row=2, column=2, columnspan=1, padx=10, pady=10, sticky=tk.N)

reco_exten_frame = tk.LabelFrame(root, text=' Extended Metrics ', width=23, height=22)
reco_exten_frame.grid(row=2, column=3, padx=10, pady=10, sticky=tk.N)

reco_overview_frame = tk.LabelFrame(root, text=' Risk Overview ', width=23, height=22)
reco_overview_frame.grid(row=2, column=4,padx=10, pady=10, sticky=tk.N)




# Lables to show calculated results
#rir_mean_value = tk.Label(results_frame, textvariable = rir_mean )
#attri_order_value = tk.Label(results_frame, textvariable = attri_order )
r_uq_value = tk.Label(results_frame, textvariable = r_uq )
r_uf_value = tk.Label(results_frame, textvariable = r_uf )
r_mm_tm1_value = tk.Label(results_frame, textvariable = r_mm_tm1 )
r_mm_tm2_value = tk.Label(results_frame, textvariable = r_mm_tm2 )

k_anon_value = tk.Label(results_frame, textvariable = k_anon )
l_dive_value = tk.Label(results_frame, textvariable = l_dive )
t_clos_value = tk.Label(results_frame, textvariable = t_clos )

dataset_info_label = tk.Label(root, textvariable = dataset_info)
exec_time_label = tk.Label(root, textvariable = exec_time_tk)

# Text widget for recommendations
#results_text = tk.Text(results_frame, height = 10, width = 70)
#reco_conven_text = tk.Text(reco_conven_frame, height = 7, width = 30)
#reco_exten_text = tk.Text(reco_exten_frame, height = 7, width = 40)
#reco_mm_text = tk.Text(reco_exten_frame, height = 10, width = 50)

# Canvas & shapes for recommendations

canvas_1 = tk.Canvas(reco_conven_frame, width=180, height=100)
canvas_1.grid(row=2, column=3)

fill_color_init = 'gray65'

cir_k = canvas_1.create_oval(90, 10, 110, 30, fill=fill_color_init, width=0)
cir_l = canvas_1.create_oval(90, 40, 110, 60, fill=fill_color_init, width=0)
cir_t = canvas_1.create_oval(90, 70, 110, 90, fill=fill_color_init, width=0)
cir_conven_metrics = canvas_1.create_oval(130, 30, 170, 70, fill=fill_color_init, width=0)

text_k = canvas_1.create_text(45, 19, text="k-anonymity", fill="black", justify=tk.RIGHT)
text_l = canvas_1.create_text(45, 49, text="l-diversity", fill="black", justify=tk.RIGHT)
text_t = canvas_1.create_text(45, 79, text="t-closeness", fill="black", justify=tk.RIGHT)


canvas_2 = tk.Canvas(reco_exten_frame, width=180, height=100)
canvas_2.grid(row=2, column=3)

cir_uq = canvas_2.create_oval(90, 10, 110, 30, fill=fill_color_init, width=0)
cir_uf = canvas_2.create_oval(90, 40, 110, 60, fill=fill_color_init, width=0)
cir_co = canvas_2.create_oval(90, 70, 110, 90, fill=fill_color_init, width=0)
cir_exten_metrics = canvas_2.create_oval(130, 30, 170, 70, fill=fill_color_init, width=0)

text_uq = canvas_2.create_text(45, 19, text="Uniqueness", fill="black", justify=tk.RIGHT)
text_uf = canvas_2.create_text(45, 49, text="Uniformity", fill="black", justify=tk.RIGHT)
text_co = canvas_2.create_text(45, 79, text="Correlation", fill="black", justify=tk.RIGHT)

canvas_3 = tk.Canvas(reco_overview_frame, width=100, height=100)
canvas_3.grid(row=2, column=3)
cir_overview = canvas_3.create_oval(15, 15, 85, 85, fill=fill_color_init, width=0)







### Widgets layouting
i = 0
k = 0

r_uq_value.grid(row=i+1, column=k+1, padx=2, pady=2, sticky=tk.W)
r_uf_value.grid(row=i+2, column=k+1, padx=2, pady=2, sticky=tk.W)
r_mm_tm1_value.grid(row=i+3, column=k+1, padx=2, pady=2, sticky=tk.W)
r_mm_tm2_value.grid(row=i+4, column=k+1, padx=2, pady=2, sticky=tk.W)

k_anon_value.grid(row=i+5, column=k+1, padx=2, pady=2, sticky=tk.W)
l_dive_value.grid(row=i+6, column=k+1, padx=2, pady=2, sticky=tk.W)
t_clos_value.grid(row=i+7, column=k+1, padx=2, pady=2, sticky=tk.W)

dataset_info_label.grid(row=1, column=0, padx=10, pady=10, columnspan=3, sticky=tk.W)
exec_time_label.grid(row=i+7, column=0, padx=10, pady=10, columnspan=3, sticky=tk.W)

## Complience to GDPR
#reco_conven_text.grid(row=i+1, column=k+2, padx=10, pady=10, columnspan=3, sticky=tk.W)

## Complience to extended metrics
#results_text.grid(row=i+2, column=k, padx=2, pady=2, columnspan=3, sticky=tk.W)
#uqufco_reco_label.grid(row=i+1, column=k+3, padx=2, pady=2, columnspan=3, sticky=tk.W)
#reco_exten_text.grid(row=i+2, column=k+3, padx=10, pady=10, columnspan=3, sticky=tk.W)
#mm_reco_label.grid(row=i+3, column=k+3, padx=2, pady=2, columnspan=3, sticky=tk.W)
#reco_mm_text.grid(row=i+4, column=k+3, padx=10, pady=10, columnspan=3, sticky=tk.W)

tk.mainloop()