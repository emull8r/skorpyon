# AI for smart port scanner

from pickletools import optimize
import numpy as np
import random
import os
import torch as torch
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

    # Add an event to the memory
    def push(self, event):
        self.memory.append(event)
        if len(self.memory > self.capacity):
            del self.memory[0]

    # Get a sample of our memory  
    def sample(self, batch_size):
        samples = zip(*random.sample(self.memory, batch_size))
        return map(lambda x: Variable(torch.cat(x, 0)), samples)
    
class Dqn:

    def __init__(self, input_size, output_size, hidden_layer_size, capacity, gamma, reward_window_size = 1000, learning_rate=0.001):
        self.gamma = gamma
        self.reward_window = []
        self.reward_window_size = reward_window_size
        self.model = Network(input_size=input_size, output_size=output_size, hidden_layer_size=hidden_layer_size)
        self.memory = ReplayMemory(capacity=capacity)
        self.optimizer = optim.Adam(self.model.parameters(), lr = learning_rate)
        self.last_state = torch.Tensor(input_size).unsqueeze(0) # Need to add fake dimension corresponding to batch
        self.last_action = 0 # Initialize action
        self.last_reward = 0 # Initialize last reward
        self.file_name = 'brain.pth'
        self.state_key = 'state_dict'
        self.optimizer_key = 'optimizer'

    def select_action(self, state, temperature=90):
        probabilities = F.softmax(self.model(Variable(state, volatile = True))*temperature)
        action = probabilities.multinomial()
        return action.data[0, 0]

    def learn(self, batch_state, batch_next_state, batch_reward, batch_action):
        # We only want the action that was chosen
        outputs = self.model(batch_state).gather(1, batch_action.unsqueeze(1)).squeeze(1)
        next_outputs = self.model(batch_next_state).detach().max(1)[0]
        target = self.gamma * next_outputs + batch_reward
        td_loss = F.smooth_l1_loss(outputs, target)
        self.optimizer.zero_grad()
        #Backpropagate the TD loss
        td_loss.backward(retain_variables = True)
        self.optimizer.step()

    def update(self, reward, signal, number_of_samples=100):
        # The signal should be a list. It must be converted to a torch tensor.
        new_state = torch.Tensor(signal).float().unsqueeze(0)
        #Make sure last action is an int
        last_action =  int(self.last_action)
        self.memory.push((self.last_state, new_state, torch.LongTensor([last_action]), torch.Tensor([self.last_reward])))
        # Play an action after entering new state
        action = self.select_action(new_state)
        #Start learning from actions in the last events
        if len(self.memory.memory > number_of_samples):
            batch_state, batch_next_state, batch_reward, batch_action = self.memory.sample(number_of_samples)
            self.learn(batch_state, batch_next_state, batch_reward, batch_action)
        self.last_action = action
        self.last_state = new_state
        self.last_reward = reward
        self.reward_window.append(reward)
        if len(self.reward_window) > self.reward_window_size:
            del self.reward_window[0]
        return action

    def score(self):
        denominator = len(self.reward_window)
        if denominator == 0:
            denominator = 1
        mean = sum(self.reward_window) / denominator
        return mean

    def save(self):
        torch.save({self.state_key: self.model.state_dict(),
        self.optimizer_key: self.optimizer.state_dict,
        }, self.file_name)

    def load(self):
        if os.path.isfile(self.file_name):
            print('-> Loading checkpoint ...')
            checkpoint = torch.load(self.file_name)
            self.model.load_state_dict(checkpoint[self.state_key])
            self.model.load_state_dict(checkpoint[self.optimizer_key])
            print('Loaded checkpoint')
        else:
            print('Checkpoint ' + self.file_name + ' not found.')
