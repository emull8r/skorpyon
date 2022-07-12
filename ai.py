# AI for smart port scanner

import numpy as np
import random
import os
import torch
import torch.nn as nn
import torch.nn.functional as F
import torch.optim as optim
import torch.autograd as autograd
from torch.autograd import Variable

class Network(nn.Module):

    def __init__(self, input_size, output_size, hidden_layer_size):
        super(Network, self).__init__()
        self.input_size = input_size # Number of input neurons
        self.output_size = output_size # Number of output neurons
        # Scan types: SYN, XMAS, FIN, NULL, ACK, Window, and UDP = 7 actions
        # Ports: 0 - 65535 = 65536 ports
        # 7 + 65536 = 65543 input neurons
        # Or, what if we had a separate neural network for each type of scan?
        self.hidden_layer = hidden_layer_size
        self.fc1 = nn.Linear(input_size, self.hidden_layer)
        self.fc2 = nn.Linear(self.hidden_layer, output_size)

    def get_q_values(self, state):
        # Get Q-values from neural network
        x = F.relu(self.fc1(state))
        q_values = self.fc2(x)
        return q_values

class ReplayMemory(object):

    def __init__(self, capacity):
        self.capacity = capacity
        self.memory = []