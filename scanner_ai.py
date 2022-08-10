"""AI for the deep learning portion of the scanner."""

import random
import os
import torch
import torch.nn as nn
import torch.nn.functional as F
import torch.optim as optim
from torch.autograd import Variable

class Network(nn.Module):
    """A generic class uses to hold and manage a neural network with one hidden layer."""

    def __init__(self, input_size, output_size, hidden_layer_size):
        super(Network, self).__init__()
        self.input_size = input_size # Number of input neurons
        self.output_size = output_size # Number of output neurons
        self.hidden_layer = hidden_layer_size
        self.fc1 = nn.Linear(input_size, self.hidden_layer)
        self.fc2 = nn.Linear(self.hidden_layer, output_size)

    def forward(self, state):
        """Get the Q-Values (output) from the Deep Q-Learning model.

            Keyword arguments:
            state -- The state of the model to get the outputs from.
        """
        q_tensor = F.relu(self.fc1(state))
        q_values = self.fc2(q_tensor)
        return q_values

class ReplayMemory(object):
    """A class used to store past actions of the AI.
    This memory is necessary for deep learning to work."""
    def __init__(self, capacity):
        self.capacity = capacity
        self.memory = []

    def push(self, event):
        """Append an event to the memory."""
        self.memory.append(event)
        if len(self.memory) > self.capacity:
            del self.memory[0]

    def sample(self, batch_size):
        """Get a sample of our memory of size batch_size."""
        samples = zip(*random.sample(self.memory, batch_size))
        return map(lambda iterator: Variable(torch.cat(iterator, 0)), samples)

class Brain:
    """The 'Brain' of a Deep Q-Learning network, used to drive scanning decisions."""
    def __init__(self, input_size, output_size, hidden_layer_size=30,
        capacity=1000, gamma=0.9, reward_window_size=1000, learning_rate=0.005):
        self.gamma = gamma
        self.reward_window = []
        self.reward_window_size = reward_window_size
        self.model = Network(input_size=input_size, output_size=output_size,
                            hidden_layer_size=hidden_layer_size)
        self.memory = ReplayMemory(capacity=capacity)
        self.optimizer = optim.Adam(self.model.parameters(), lr = learning_rate)
        # Need to add fake dimension corresponding to batch
        self.last_state = torch.Tensor(input_size).unsqueeze(0)
        self.last_action = [1, 0, 0, 0, 0, 0] # Initialize action
        self.last_reward = 0 # Initialize last reward
        self.file_name = 'brain.pth'
        self.state_key = 'state_dict'
        self.optimizer_key = 'optimizer'

    def select_action(self, state, temperature=90, n_samples=50):
        """Choose the next action to take

            Keyword arguments:
            state -- The state of the model
            temperature -- Adjusts how confident the AI is in its chosen probabilities.
                            A higher temperature makes the AI more confident.
            n_samples -- The number of samples for the multinomial to draw from.
        """
        #TODO: AI just always chooses 0 (SYN scan). Fix this.
        print("Softmax: ",self.model(Variable(state))*temperature)
        probabilities = F.softmax(self.model(Variable(state))*temperature, dim=1)
        print("Probabilities: ",probabilities)
        #action = probabilities.multinomial(n_samples, replacement=True)
        action = probabilities.data[0]
        #return action.data[0, 0]
        return action

    def learn(self, batch_state, batch_next_state, batch_reward, batch_action):
        """Make the AI learn from a whole batch of past actions, states, and rewards.

            Keyword arguments:
            batch_state -- A batch of previous states
            batch_next_state -- A corresponding batch of subsequent states
            batch_reward -- A corresponding batch of rewards
            batch_action -- A corresponding batch of actions
        """
        # TODO: Figure out how to use this
        outputs = self.model(batch_state).gather(1, batch_action.unsqueeze(1)).squeeze(1)
        next_outputs = self.model(batch_next_state).detach().max(1)[0]
        target = self.gamma * next_outputs + batch_reward
        td_loss = F.smooth_l1_loss(outputs, target)
        self.optimizer.zero_grad()
        # Backpropagate the TD loss
        td_loss.backward(retain_graph=True)
        self.optimizer.step()

    def int_to_action(self, integer):
        """Convert an integer from 0-5 to an array of 1s and 0s corresponding to the action."""
        syn = 0
        xmas = 0
        fin = 0
        null = 0
        window = 0
        udp = 0
        if integer == 0:
            syn = 1
        elif integer == 1:
            xmas = 1
        elif integer == 2:
            fin = 1
        elif integer == 3:
            null = 1
        elif integer == 4:
            window = 1
        elif integer == 5:
            udp = 1
        return [syn, xmas, fin, null, window, udp]

    #TODO: Make n_samples a command line parameter, or better yet, pull past events based on port
    def update(self, reward, signal, n_samples=50):
        """Update the model. Enter the new state, start learning, and get the new last reward.
            Keyword arguments:
            reward -- The new reward from entering the new state
            signal -- The inputs that triggers entering the new state
            n_samples -- The number of samples of past events in memory to use for learning
        """
        # The signal should be a list. It must be converted to a torch tensor.
        new_state = torch.Tensor(signal).float().unsqueeze(0)
        # Make sure last action is an int
        last_action =  self.last_action
        self.memory.push((self.last_state,
                            new_state,
                            torch.LongTensor(last_action),
                            torch.LongTensor([self.last_reward])))
        if len(self.memory.memory) > n_samples:
            # Play an action after entering new state
            print('AI-chosen scan')
            action = self.select_action(new_state)
            # Start learning from actions in the last events
            batch_state,batch_next_state,batch_action,batch_reward = self.memory.sample(n_samples)
            self.learn(batch_state, batch_next_state, batch_reward, batch_action)
        else:
            # Choose a random scan type
            print('Randomized scan')
            action = torch.LongTensor(self.int_to_action(random.randint(0, 5)))
        self.last_action = action
        self.last_state = new_state
        self.last_reward = reward
        self.reward_window.append(reward)
        if len(self.reward_window) > self.reward_window_size:
            del self.reward_window[0]
        return action

    def score(self):
        """Get the mean of the past rewards."""
        denominator = len(self.reward_window)
        if denominator == 0:
            denominator = 1
        mean = sum(self.reward_window) / denominator
        return mean

    def save(self):
        """Save the model to the machine."""
        torch.save({self.state_key: self.model.state_dict(),
        self.optimizer_key: self.optimizer.state_dict(),
        }, self.file_name)

    def load(self):
        """Load the model saved to the machine."""
        if os.path.isfile(self.file_name):
            print('-> Loading checkpoint ...')
            checkpoint = torch.load(self.file_name)
            self.model.load_state_dict(checkpoint[self.state_key])
            self.optimizer.load_state_dict(checkpoint[self.optimizer_key])
            print('Loaded checkpoint')
        else:
            print('Checkpoint ' + self.file_name + ' not found.')
