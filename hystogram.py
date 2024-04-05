import matplotlib.pyplot as plt

# Sample data for two categories
data1 = [1, 2, 3, 4, 5]
data2 = [2, 3, 3, 4, 4]

# Creating subplot with 1 row and 2 columns
fig, axs = plt.subplots(1, 2, figsize=(10, 5))

# Plotting first histogram
axs[0].hist([data1, data2], bins=5, stacked=True, label=['Category 1', 'Category 2'])
axs[0].set_title('Stacked Histogram - Category 1 vs Category 2')
axs[0].legend()

# Plotting second histogram
axs[1].hist([data1, data2], bins=5, stacked=True, label=['Category 1', 'Category 2'], orientation='horizontal')
axs[1].set_title('Stacked Histogram - Category 1 vs Category 2 (Horizontal)')
axs[1].legend()

plt.tight_layout()
plt.show()